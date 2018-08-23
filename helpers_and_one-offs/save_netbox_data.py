#!/usr/bin/env python3

try:
  import requests
  import getpass
  import json
  import socket
  import argparse
  import logging
  import sys
  import time
  from http.client import HTTPConnection
  #
  # In the makeDrive.php environment, the lines below cause an error.
  # Traceback (most recent call last):
  #   File "./build.py", line 13, in <module>
  #     from requests.packages.urllib3.exceptions import InsecureRequestWarning
  # ImportError: No module named packages.urllib3.exceptions
  # If NetBox has a self-signed cert, API calls without the
  # InsecureRequestWarning would fail
  #
  if sys.version_info >= (2,7,14):
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
  import re
  import csv
except ImportError as e:
  print("CRITICAL: Module Import error: {}".format(e))
  exit(1)

my_version = 0.3

#
# Variables and the like
#
httpSuccessCodes = [200, 201, 202, 204]


global netbox_data
netbox_data = {}
global yaml_config
yaml_config = {
  'netbox_host' : "netbox.datto.net",
  'netbox_port' : "443",
  'api_key' : None,
  'protocol': 'https',
  'url_headers' : {
    "Content-Type": "application/json",
    "Accept": "application/json"
  }
}

def parse_args():
  """Sets up the `args` namespace object containing all the passed arguments.
  Uses the argparse module
  """
  parser = argparse.ArgumentParser(prog='NetboxDataDumper', description="Save NetBox data as a giant JSON, version {}".format(my_version))
  parser.add_argument('--config', help='Path to the YAML config file', required = True)
  parser.add_argument('--netbox_host', help='Remote host against which to run. Default: {}'.format(yaml_config['netbox_host']))
  parser.add_argument('--netbox_port', help='Remote host port against which to run. Default: {}'.format(yaml_config['netbox_port']))
  parser.add_argument('--verbose', help='Make things chatty.', action='store_true')
  parser.add_argument('--print_json', help='Print the JSON as part of the verbose output.', action='store_true')
  parser.add_argument('--requestsdebug', help='Set the debug dial of the URL Requests library to 11. Or 1. Makes it quite chatty.', action='store_true')
  parser.add_argument('--logfile', help='Path to the logfile. If empty, output is STDOUT/STDERR, which implies something else handling logfile(s). Typically useful with --verbose')
  parser.add_argument('--timestamp', help='Should timestamps be printed?', action='store_true')
  parser.add_argument('--ssl', help='Should the connection be treated as an SSL/TLS protected connection?', action='store_true', default = True)
  parser.add_argument('--savefile', help='Filename into which to save the gathered initial state of things.')
  parser.add_argument('--api_endpoint_results_savefile', help='')

  global args
  args = parser.parse_args()

  if args.netbox_host:
    yaml_config['netbox_host']=args.netbox_host

  if args.netbox_port:
    yaml_config['netbox_port']=args.netbox_port


def setup_logging():
    """ Initialize the logging fiddly bits
    """
  
    #
    #
    #  Initialize logger object, with a definitive name
    #
    global logger
    logger = logging.getLogger('Netbox_Saltinator')
    # Set "lowest" level of logging
    logger.setLevel(logging.DEBUG)
    # Setup handling output to the console, and set the "lowest" logging level
    log_to_console = logging.StreamHandler()
    log_to_console.setLevel(logging.DEBUG)

    #
    # Set the default format of the logger
    #
    if args.timestamp:
      if args.verbose:
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(processName)s[%(threadName)s|%(funcName)s] - %(message)s')
      else:
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    else:
      if args.verbose:
        formatter = logging.Formatter('%(levelname)s - %(processName)s[%(threadName)s|%(funcName)s] - %(message)s')
      else:
        formatter = logging.Formatter('%(levelname)s - %(message)s')
    #
    # Set the console output format.
    #
    log_to_console.setFormatter(formatter)
    #
    # If the --logfile parameter is specified, check if its target is writeable, and if it is, start logging to it.
    # If not, error out.
    #
    try:
      if args.logfile:
        log_to_file = logging.FileHandler(args.logfile)
        log_to_file.setLevel(logging.DEBUG)
        log_to_file.setFormatter(formatter)
        logger.addHandler(log_to_file)
        if args.verbose:
          logger.info("Startup")
      else:
        logger.addHandler(log_to_console)
        if args.verbose:
          logger.info("Startup")
    except IOError as e:
      logger.critical("Error trying to open {} error({}): {}".format(args.logfile, e.errno, e.strerror))


def handle_yaml_config():
  """Opens a named file as a YAML config file. Verifies that all mandatory values are present.
  Stuffs the config data into a global yaml_config dictionary
  """
  try:
    import yaml
    with open(args.config,'r') as yaml_config_fp:
      yaml_blob = yaml.safe_load(yaml_config_fp)
      #
      #
      mandatory_config = []
      config_ok = ''
      for config_item in mandatory_config:
        if args.verbose: logger.debug("Mandatory Config entry: '{}'".format(config_item))
        if config_item not in yaml_blob.keys():
          logger.critical("Mandatory setting '{}' not in config file '{}'!".format(config_item, args.config))
          config_ok = False
      if config_ok == False:
        logger.critical("One or more mandatory config settings missing from config file!")
        exit(1)
      else:
        for key in yaml_blob.keys():
          yaml_config[key] = yaml_blob[key]
    yaml_config_fp.close()

  except IOError as e:
    logger.critical("Error trying to open {} error({}): {}".format(args.config, e.errno, e.strerror))
    exit(1)


def netbox_query_endpoint(api_endpoint):
  """Queries, with pagination support, a particular NetBox API RESTful endpoint.
  Stuffs output into an in-memory data structure based on the api_endpoint variable
  hashed on the `hashkey` setting from the `yaml_config['netbox_api_endpoints']` list defined elsewhere
  """
  URL_BASE = "{}:{}".format(yaml_config['netbox_host'],yaml_config['netbox_port'])
  #
  # Now with SESSIONS
  #
  api_endpoint_results = []
  logger.info("Querying NetBox API endpoint '{}'".format(api_endpoint))
  request_url = "{}://{}{}?limit=1000".format(
    yaml_config['protocol'],
    URL_BASE,
    yaml_config['netbox_api_endpoints'][api_endpoint]['url']
    )
  if args.verbose: 
    logger.debug("  Request_url: '{}', Method: '{}', hashkey: '{}'"
    .format(
      request_url,
      'GET',
      yaml_config['netbox_api_endpoints'][api_endpoint]['hashkey']
      )
    )
  try:
    if args.requestsdebug: HTTPConnection.debuglevel = 1
    conn = netbox_session.get(request_url, headers=yaml_config['url_headers'], verify=False)
    if args.verbose: logger.debug("  Response: {}, reason: {}".format(conn.status_code, conn.reason))
    if conn.status_code in httpSuccessCodes:
      conn_json = conn.json()
      conn_json_count = conn_json['count']
      #
      # The 'results' is a list. Iterating through it and storing it as individual entries
      #
      # Later, will walk the whole thing, and make it into a DICT
      #
      for result in conn_json['results']:
        api_endpoint_results.append(result)
      
      logger.info("  Endpoint results to be processed: {}".format(conn_json_count))
      if conn_json['next'] is not None and (conn_json_count > len(api_endpoint_results)):
        if args.verbose:
          logger.debug("  URL for next batch is: {}".format(conn_json['next']))
          logger.debug("  API endpoint '{}' returned data indicating paginated results. Obliging.".format(api_endpoint))
      while conn_json_count > len(api_endpoint_results):
        if conn_json['next'] is not None:
          next_url = conn_json['next']
          if args.verbose:
            logger.debug("    Have: {}, but should have {}".format(len(api_endpoint_results), conn_json_count))
            logger.debug("    Querying URL: '{}'".format(next_url))
          conn = netbox_session.get(next_url, headers=yaml_config['url_headers'])
          conn_json = conn.json()
          #
          # The 'results' is a list. Iterating through it and storing it as individual entries
          #
          # Later, will walk the whole thing, and make it into a DICT
          #
          for result in conn_json['results']:
            api_endpoint_results.append(result)
          if args.verbose: logger.debug("    This batch upped the total results to: {}".format(len(api_endpoint_results)))

      netbox_data[api_endpoint] = {}

      #
      # If there is no data, in the JSON, well, then, let's not do anything.
      #
      if conn_json_count > 0:
        #
        # Special for PMay
        #
        if args.api_endpoint_results_savefile:
          logger.debug("Saving {} items in api_endpoint_results to: '{}'"
            .format(
              len(api_endpoint_results),
              args.api_endpoint_results_savefile
            )
          )
          with open(args.api_endpoint_results_savefile, 'w') as debug_savefile_wtaf:
            save_string = '\n'.join((str(result) for result in api_endpoint_results))
            debug_savefile_wtaf.write(save_string)
            # for result in api_endpoint_results:
            #   #
            #   # 'result' element is a DICT. So, have to turn it into string.
            #   #
            #   debug_savefile_wtaf.write(json.dumps(result))
        #
        # Not all entries from NetBox have a 'name' properties ('interface-connections', for example, do not).
        # But, keying/hashing on 'name' is useful for quick lookups, so when that's available, it is used.
        #
        netbox_api_hashkey = yaml_config['netbox_api_endpoints'][api_endpoint]['hashkey']

        if ('name' not in conn_json['results'][0].keys()) and ('id' not in conn_json['results'][0].keys()):
          if args.verbose: logger.warning("  API endpoint '{}' data does not have a 'name' OR 'id' property!".format(api_endpoint))

        #
        # NetBox slugs and names aren't case sensitive, but when used as keys in the DICTs, they become so.
        # Force all to lower-case
        #
        # if netbox_api_hashkey == 'slug' or netbox_api_hashkey == "name":
        if netbox_api_hashkey == 'slug':
          if args.verbose: logger.debug("API Endpoint: {} is keyed on 'slug'. Using lowercase".format(api_endpoint))
          for result in api_endpoint_results:
            netbox_data[api_endpoint][result[netbox_api_hashkey].lower()] = result
        elif netbox_api_hashkey == 'id':
          if args.verbose: logger.debug("API Endpoint: {} is keyed on 'id'. Force-casting to int".format(api_endpoint))
          dupes = 0
          for result in api_endpoint_results:
            result_id = int(result[netbox_api_hashkey])
            if result_id in list(netbox_data[api_endpoint]):
              dupes += 1
              logger.critical("ResultID {} already stored in netbox_data['{}']. WTAF?"
                .format(
                  result_id,
                  api_endpoint
                )
              )
              # logger.debug("Original: {}, already stored: {}"
              #   .format(
              #     json.dumps(result, indent = 2),
              #     json.dumps(netbox_data[api_endpoint][result_id], indent = 2)
              #   )
              # )
            netbox_data[api_endpoint][result_id] = result
          logger.debug("Dupes: {}".format(dupes))
        else:
          for result in api_endpoint_results:
            netbox_data[api_endpoint][result[netbox_api_hashkey]] = result
    else:
      logger.warning("NetBox API endpoint query returned code: {}, '{}'".format(conn.status_code, conn.message))
    if args.verbose: logger.debug("  Read in Netbox endpoint data: '{}' (entries returned: {})"
      .format(
        api_endpoint,
        len(netbox_data[api_endpoint].keys())
        )
      )
  except ValueError as e:
    logger.critical("Got the following data back: {}".format(data))
    logger.critical("JSON parse error: {}".format(e))
    exit(1)
  except socket.error as e:
    logger.critical("ERROR: Socket Error")
    logger.critical("Tried to access '{}://{}{}'".format(protocol, URL_BASE, netbox_api_endpoint))
    logger.critical("ERROR: {}".format(e))
    exit(1)


def rekey_network_interfaces():
  """Re-parses `netbox_data['interfaces']` dataset into
  `netbox_data['devices'][$DEVICE_NAME]['interfaces']`
  """
  try:
    curr_int = 1
    if 'interfaces' in list(netbox_data.keys()):
      #
      # Let's re-key the netbox_data['interfaces'] dataset to be organized
      # by the symbolic name of the host on which they are living.
      # So, in the end, the structure will look like this:
      # netbox_data['devices'][$DEVICE_NAME]['interfaces'][$interface_name] = { $InterfaceDataStruct }
      # Example:
      # netbox_data['devices']["server1234"]['interfaces']["eth0"]
      # The use of the symbolic name for device key is deliberate, since this is how Salt
      # processes systems, but other properties like mobo SN and eth0 MAC address
      # can be used for a cross-check.
      #
      # Additional benefit is that deleting a "device" from an in-memory data structure
      # will also delete its "interfaces"
      #
      logger.info("Adding the NICs under the respective devices.")
      netbox_interface_rewalk_time_start = time.time()
      for netbox_interface_id in netbox_data['interfaces']:
        netbox_interface = netbox_data['interfaces'][netbox_interface_id]
        netbox_interface_name = netbox_data['interfaces'][netbox_interface_id]['name']
        #
        # Can this even happen? An 'interface' without a device?
        #
        if 'device' in netbox_interface.keys() and netbox_interface['device'] is not None:
          parent_device_name = netbox_interface['device']['name']
          parent_device_id = netbox_interface['device']['id']
          #
          # Bit convoluted, but here's the goal:
          # If the interface's device's name is already in the netbox_data['devices'] tree,
          # *and* numeric ID matches (because I don't trust matches on hostname),
          # add the whole interface NIC data structure to the parent.
          #
          if parent_device_name in list(netbox_data['devices'].keys()):
            if parent_device_id == netbox_data['devices'][parent_device_name]['id']:
              if args.verbose: logger.debug("({} of {}) Adding interface '{}'({}) to list of interfaces on device '{}' ({})".format(
                curr_int,
                len(netbox_data['interfaces'].keys()),
                netbox_interface['name'],
                netbox_interface['id'],
                parent_device_name,
                parent_device_id)
                )
              curr_int += 1
              #
              # add_rekeyed_structures() should make sure that the 'interfaces' structure exists for all devices in memory
              #
              netbox_data['devices'][parent_device_name]['interfaces'][netbox_interface_name] = netbox_interface
              if args.verbose: logger.debug("  Total NICS on '{}'({}): {}".format(
                parent_device_name,
                parent_device_id,
                len(netbox_data['devices'][parent_device_name]['interfaces']))
                )
              #
              # Tried deleting the interface out of the API-query-generated
              # structure, but that caused a "changed while iterating"
              # exception.
              # A bit wasteful in memory, but not strictly necessary, so
              # ignoring for now. Ultimately, would be useful to catch
              # interfaces which weren't assigned to a parent device
              # in the netbox_data['devices'] structure.
              #
              # del netbox_data['interfaces'][netbox_interface_id]

          else:
            logger.warning("Hrmm... NIC '{}' is of '{}'({}), but that device isn't in netbox_data['devices']".format(
              netbox_interface_name,
              parent_device_name,
              parent_device_id)
              )
      netbox_interface_rewalk_time_end = time.time()
      if args.verbose: logger.debug("Interfaces re-walk complete. Time taken: {}".format(netbox_interface_rewalk_time_end - netbox_interface_rewalk_time_start))

    else:
      logger.warning("The netbox_data structure does not seem to contain 'interfaces'. Halp?")
      exit(1)
    #
    # Hokay, lets see what I've wrought
    #
    # logger.debug("Interfaces length: {}".format(len(netbox_data['interfaces'])))
    # time.sleep(10)
  except TypeError as e:
    logger.warning("NetBox NIC re-walk TypeError: {}".format(e))
    logger.warning("NIC NetBox ID: {}".format(netbox_interface_id))
    exit(1)
  except KeyError as e:
    logger.warning("NIC Re-Key WALK KeyError in: {}".format(json.dumps(netbox_interface, sort_keys=True, indent=2)))
    logger.warning("WALK KeyError e: '{}'".format(e))
    exit(1)


def add_rekeyed_structures(*param):
  """If supplied an argument, will add the empty DICTs enumerated
  in `additions` list to the `netbox_data['devices'][$argument]` DICT.
  Else, walks the `netbox_data['devices']` DICT and adds empty DICTs
  enumerated in `additions` variable.
  """
  curr_dev = 1
  additions = ['ipaddresses', 'interfaces']
  try:
    #
    # Function calls in Python (2.7) are of type "tupple"
    # But, the len() function does the reasonable thing.
    # TODO: If going to Python 3.5, do the type hinting for params.
    #
    if len(param) == 1:
      for addition in additions:
        if addition not in list(netbox_data['devices'][param[0]].keys()):
          netbox_data['devices'][param[0]][addition] = {}
          if args.verbose: logger.debug("  {}".format(addition))
    if len(param) == 0:
      netbox_total_devices = len(netbox_data['devices'])
      if args.verbose: logger.debug("Initializing 'ipaddresses' and 'interfaces' "
        "from {} devices".format(netbox_total_devices))
      for netbox_device in netbox_data['devices']:
        if args.verbose:
          logger.debug("({} of {}) Adding 'interfaces' and "
            "'ipaddresses' to '{}'".format(
              curr_dev,
              netbox_total_devices,
              netbox_device
            )
          )
        curr_dev += 1
        for addition in additions:
          if addition not in list(netbox_data['devices'][netbox_device].keys()):
            netbox_data['devices'][netbox_device][addition] = {}
            if args.verbose: logger.debug("  {}".format(addition))
    if len(param) > 1:
      logger.warning("Was passed: '{}' ('{}')".format(netbox_device, len(netbox_device)))
      exit(1)
  except TypeError as e:
    logger.warning("AddRekeyedStruct TypeError: {}".format(e))
    exit(1)
  except KeyError as e:
    logger.warning("AddRekeyedStruct KeyError e: '{}'".format(e))
    exit(1)


def rekey_racks():
  """Reparses `netbox_data['racks']` dataset into
  `netbox_data['racks_by_site'][$SITE]`.
  By agreement of NetEng/CloudEng/SysEng/SecEng, rack names in NetBox will
  longer include a site name (so, 'DLT-A-1' becomes 'A-1'), globally keying
  them on 'name' is no longer sufficiently unique.
  Instead, they'll be re-keyed by site, and then by name under that site.
  """

  try:
    curr_rack = 1
    if 'racks' in list(netbox_data.keys()):
      if 'racks_by_site' not in list(netbox_data.keys()):
        netbox_data['racks_by_site'] = {}
      #
      # Even if the site doesn't have any racks in it, should still 
      # initialize the data structure
      #
      for site_slug in netbox_data['sites']:
        netbox_data['racks_by_site'][site_slug] = {}
      logger.info("Re-keying racks")
      for rack_id in list(netbox_data['racks'].keys()):
        rack_entry      = netbox_data['racks'][rack_id]
        rack_name       = rack_entry['name']
        rack_site_slug  = rack_entry['site']['slug'].lower()
        if args.verbose: logger.debug("|-> Rack {} (ID: {}) in site: {}"
          .format(rack_name, rack_id, rack_site_slug))
        if rack_name in list(netbox_data['racks_by_site'][rack_site_slug].keys()):
          logger.warning("Rack Name {} already seen for site {}!"
            .format(rack_name, rack_site_slug))
        else:
          netbox_data['racks_by_site'][rack_site_slug][rack_name] = rack_entry
    if args.verbose:
      logger.debug("Re-keyed racks:")
      for rack_site_slug in list(netbox_data['racks_by_site'].keys()):
        logger.debug("  Site Slug: '{}'".format(rack_site_slug))
        logger.debug("    Racks: {}".format(netbox_data['racks_by_site'][rack_site_slug].keys()))
  except TypeError as e:
    logger.critical("NetBox Racks re-walk TypeError: {}".format(e))
    logger.critical("NetBox ID of the Rack: {}".format(json.dumps(rack_entry,sort_keys=True,indent=2)))
    exit(1)
  except KeyError as e:
    logger.critical("Racks Re-Key WALK KeyError in: {}".format(json.dumps(rack_entry,sort_keys=True,indent=2)))
    logger.critical("WALK KeyError e: '{}'".format(e))
    exit(1)


def rekey_rack_groups():
  """Reparses `netbox_data['rack-groups']` dataset into
  `netbox_data['rack_groups_by_site'][$SITE]`.
  By agreement of NetEng/CloudEng/SysEng/SecEng, rack names in NetBox will
  longer include a site name (so, 'DLT-A-1' becomes 'A-1'), globally keying
  them on 'name' is no longer sufficiently unique.
  Instead, they'll be re-keyed by site, and then by name under that site.
  """

  try:
    curr_rack = 1
    if 'rack-groups' in list(netbox_data.keys()):
      if 'rack_groups_by_site' not in list(netbox_data.keys()):
        netbox_data['rack_groups_by_site'] = {}
      #
      # Even if the site doesn't have any rack groups in it, should still 
      # initialize the data structure
      #
      for site_slug in netbox_data['sites']:
        netbox_data['rack_groups_by_site'][site_slug] = {}

      logger.info("Re-keying rack_groups")
      for rack_group_id in list(netbox_data['rack-groups'].keys()):
        rack_group_entry      = netbox_data['rack-groups'][rack_group_id]
        rack_group_name       = rack_group_entry['name']
        rack_group_site_slug  = rack_group_entry['site']['slug'].lower()
        if args.verbose: logger.debug("|-> Rack Group {} (ID: {}) in site: {}"
          .format(rack_group_name, rack_group_id, rack_group_site_slug))
        if rack_group_name in list(netbox_data['rack_groups_by_site'][rack_group_site_slug].keys()):
          logger.warning("Rack Group Name {} already seen for site {}!"
            .format(rack_group_name, rack_group_site_slug))
        else:
          netbox_data['rack_groups_by_site'][rack_group_site_slug][rack_group_name] = rack_group_entry
    if args.verbose:
      logger.debug("Re-keyed racks:")
      for rack_group_site_slug in list(netbox_data['rack_groups_by_site'].keys()):
        logger.debug("  Site Slug: '{}'".format(rack_group_site_slug))
        logger.debug("    Racks Groups: {}".format(netbox_data['rack_groups_by_site'][rack_group_site_slug].keys()))
  except TypeError as e:
    logger.critical("NetBox Racks re-walk TypeError: {}".format(e))
    logger.critical("NetBox ID of the Rack: {}".format(json.dumps(rack_group_entry,sort_keys=True,indent=2)))
    exit(1)
  except KeyError as e:
    logger.critical("Rack Groups Re-Key WALK KeyError in: {}".format(json.dumps(rack_group_entry,sort_keys=True,indent=2)))
    logger.critical("WALK KeyError e: '{}'".format(e))
    exit(1)


def rekey_ip_addresses():
  """Reparses `netbox_data['ipaddresses']` dataset into
  `netbox_data['devices'][$DEVICE_NAME]['ipaddresses']`
  """
  try:
    curr_ipv4 = 1
    if 'ipaddresses' in list(netbox_data.keys()):
      #
      # Let's re-key the netbox_data['ipaddresses'] dataset to be organized
      # by the symbolic name of the host on which they are living.
      # So, in the end, the structure will look like this:
      # netbox_data['devices'][$DEVICE_NAME]['ipaddresses'][$ipaddress] = { $IPv4DataStruct }
      # Example:
      # netbox_data['devices']["server1234"]['ipaddresses']["1.2.3.4/32"]
      #
      # The use of the symbolic name for device key is deliberate, since this is how Salt
      # processes systems, but other properties like mobo SN and eth0 MAC address
      # can be used for a cross-check.
      #
      # A future iteration of this re-walk may do something else - like store
      # the IPv4 struct as a child of the Interface to which it is assigned,
      # though that seems like it'll be a very complex data structure to
      # reason about.
      #
      # Additional benefit is that deleting a "device" from an in-memory data structure
      # will also delete its IP addresses
      #
      # The netbox_data['ipaddresses'] structure is keyed on IP address,
      # rather than the numeric IP ID. This makes things interesting,
      # but useful for detecting re-used IPs in our environment.
      # Normally, those IPs would show up as "duplicate", which isn't
      # strictly accurate.
      #
      logger.info("Adding the IPs under the respective devices.")
      netbox_ipaddress_rewalk_time_start = time.time()
      for netbox_ipaddress in list(netbox_data['ipaddresses'].keys()):

        netbox_ipaddress_entry   = netbox_data['ipaddresses'][netbox_ipaddress]
        netbox_ipaddress_address = netbox_ipaddress_entry['address']
        netbox_ipaddress_id      = netbox_ipaddress_entry['id']

        if args.verbose: logger.debug("IP Address: '{}' (ID: {})".format(netbox_ipaddress_address, netbox_ipaddress_id))
        #
        # NetBox should not allow for an IP address to exist
        # with an Interface assignment, but without a "device" record for
        # the interface
        #
        # That said, an "Unassigned" IP can have a null 'interface' structure
        #
        if netbox_ipaddress_entry['interface'] is not None:
          #
          # An IP address can have either a 'device' array as part of its
          # data, or `virtual_machine`.
          #
          if netbox_ipaddress_entry['interface']['device'] is not None:
            parent_device_name = netbox_ipaddress_entry['interface']['device']['name']
            parent_device_id = netbox_ipaddress_entry['interface']['device']['id']
          else:
            parent_device_name = netbox_ipaddress_entry['interface']['virtual_machine']['name']
            parent_device_id = netbox_ipaddress_entry['interface']['virtual_machine']['id']
          if args.verbose: logger.debug("  Parent Device: '{}' (ID:{})".format(parent_device_name, parent_device_id))
          #
          # Bit convoluted, but here's the goal:
          # If the interface's device's name is already in the netbox_data['devices'] tree,
          # *and* numeric ID matches (because I don't trust matches on hostname),
          # add the whole interface NIC data structure to the parent.
          #
          if parent_device_name in list(netbox_data['devices'].keys()):
            if parent_device_id == netbox_data['devices'][parent_device_name]['id']:
              if args.verbose: logger.debug("  ({} of {}) Adding IPv4 '{}' (ID: {}) to list of IP Adddresses on device '{}' ({})".format(
                curr_ipv4,
                len(netbox_data['ipaddresses'].keys()),
                netbox_ipaddress_address,
                netbox_ipaddress_id,
                parent_device_name,
                parent_device_id)
                )
              curr_ipv4 += 1
              #
              # add_rekeyed_structures() should make sure that the 'ipaddresses' structure exists for all devices in memory
              #
              if args.verbose: logger.debug("  Total IPv4s on '{}' ({}): {}".format(
                parent_device_name,
                parent_device_id,
                len(netbox_data['devices'][parent_device_name]['ipaddresses']))
                )
              if netbox_ipaddress_address in list(netbox_data['devices'][parent_device_name]['ipaddresses'].keys()):
                logger.warning("    {} already seen as being assigned to host {}!".format(netbox_ipaddress_address, parent_device_name))
              netbox_data['devices'][parent_device_name]['ipaddresses'][netbox_ipaddress_address] = netbox_ipaddress_entry

              #
              # Tried deleting the interface out of the API-query-generated
              # structure, but that caused a "changed while iterating"
              # exception.
              # A bit wasteful in memory, but not strictly necessary, so
              # ignoring for now. Ultimately, would be useful to catch
              # interfaces which weren't assigned to a parent device
              # in the netbox_data['devices'] structure.
              #
              # del netbox_data['devices'][salt_device_name]['ipaddresses'][netbox_ipaddress_id]
          else:
            logger.warning("Hrmm... IP Address '{}' is of '{}'({}), but that device isn't in netbox_data['devices']".format(
              netbox_ipaddress_address,
              parent_device_name,
              parent_device_id)
              )
        else:
          if args.verbose: logger.debug("IP Address '{}' (ID: {}) is unassigned to a NIC. Letting it be".format(netbox_ipaddress_address, netbox_ipaddress_id))
          curr_ipv4 += 1
      netbox_ipaddress_rewalk_time_end = time.time()
      if args.verbose: logger.debug("Interfaces re-walk complete. Time taken: {}".format(netbox_ipaddress_rewalk_time_end - netbox_ipaddress_rewalk_time_start))

    else:
      logger.warning("The netbox_data structure does not seem to contain 'ipaddresses'. Halp?")
      exit(1)
    #
    # Hokay, lets see what I've wrought
    #
    # logger.debug("Interfaces length: {}".format(len(netbox_data['ipaddresses'])))
    # time.sleep(10)
  except TypeError as e:
    logger.critical("NetBox IP re-walk TypeError: {}".format(e))
    logger.critical("NetBox ID of the IPv4: {}".format(json.dumps(netbox_ipaddress_entry,sort_keys=True,indent=2)))
    exit(1)
  except KeyError as e:
    logger.critical("IP Re-Key WALK KeyError in: {}".format(json.dumps(netbox_ipaddress_entry,sort_keys=True,indent=2)))
    logger.critical("WALK KeyError e: '{}'".format(e))
    exit(1)


def get_netbox_data():
  netbox_api_iteration_time_start = time.time()
  logger.info("Querying NetBox data. Total of {} endpoints.".format(len(yaml_config['netbox_api_endpoints'].keys())))
  if args.verbose: logger.debug("Have the following NetBox API endpoints: '{}'. Iterating over them.".format(yaml_config['netbox_api_endpoints'].keys()))
  netbox_data_itemcount = 0
  for netbox_api_endpoint in yaml_config['netbox_api_endpoints'].keys():
    netbox_query_endpoint(netbox_api_endpoint)
    netbox_data_itemcount = netbox_data_itemcount + len(netbox_data[netbox_api_endpoint].keys())
  netbox_api_iteration_time_end = time.time()
  if args.verbose: 
    logger.debug("NetBox API endpoints query complete. Time taken: {}, items read: {}".format(netbox_api_iteration_time_end - netbox_api_iteration_time_start, netbox_data_itemcount))
    logger.info("Stats:")
    for api_endpoint in netbox_data.keys():
      logger.info("\tEndpoint: {}, count: {}".format(api_endpoint, len(netbox_data[api_endpoint].keys())))

  if 'devices' in list(netbox_data.keys()):
    add_rekeyed_structures()

    rekey_network_interfaces()

    rekey_ip_addresses()

    rekey_racks()

    rekey_rack_groups()
  else:
    logger.warning("Special use detected. YMWV")


def main():
  try:

    parse_args()
    setup_logging()
    handle_yaml_config()

    #
    # Useful for seeing how the arguments got parsed
    #
    if args.verbose:
      logger.debug("****** Verbose mode ****")
      for arg in vars(args):
        logger.debug("Argument: {}".format(arg))
        logger.debug("|-> Value: {}".format(getattr(args, arg)))
      logger.debug("Config: {}".format(json.dumps(yaml_config, sort_keys = True, indent = 2)))

    #
    # The "Sessions" are the new Hawtness here:
    # http://docs.python-requests.org/en/master/user/advanced/
    # The Session object allows you to persist certain parameters across requests.
    # It also persists cookies across all requests made from the Session instance,
    # and will use urllib3's connection pooling. So if you're making several requests
    # to the same host, the underlying TCP connection will be reused, which can
    # result in a significant performance increase (see HTTP persistent connection).
    #
    global netbox_session
    netbox_session = requests.Session()
    if 'api_key' in yaml_config.keys():
        api_key = yaml_config['api_key']
        yaml_config['url_headers']["Authorization"] = "Token {}".format(api_key)
     
    netbox_session.headers.update(yaml_config['url_headers'])

    #
    # Initial httplib-used variables
    #
    #
    # URL bases

    if args.ssl:
      protocol="https"
    else:
      protocol="http"

    

    if args.savefile:
      try:
        savefile = open(args.savefile, 'w+')
        logger.info("Writing out the gathered state to: '{}'".format(args.savefile))
      except IOError as e:
        logger.critical("Error trying to open JSON savefile '{}' error({}): {}".format(args.out_file, e.errno, e.strerror))
        sys.exit(1)


    get_netbox_data()

    if args.savefile:
      json.dump(netbox_data, savefile)
      savefile.close()
  except KeyboardInterrupt:
      logger.info("Got a CTRL-C interrupt (or similar). Cleaning up.")
      if args.logfile: log_to_file.close()
      if args.savefile: savefile.close()

if __name__ == '__main__':
  main()
