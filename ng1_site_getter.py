import requests
import json
import sys
import os
import csv
import time
import string
import re
from datetime import date, datetime
from cryptography.fernet import Fernet
import logging
import numpy as np
import pandas as pd
import pprint
import argparse
import cmath

"""This program reads in a credentials file, uses that info to connect to a NetScout nGeniusONE server and authenticate.
Then it looks for a CSV file with "current" as part of its name in the local directory.
If the 'current' CSV file is found, it will read that file into a pandas dataframe for comparison later.
Also, if it finds one, it will rename the file to create a backup copy in the local directory with "archive" in the name.
Then it makes an API request to get the configuration attributes for all sites as they exist "right now" in the system.
Then it takes that "right now" site data in json format and translates it into a pandas dataframe that
 matches the schema of the "current" dataframe.
If it doesn't find a "current" CSV files (firt time run), it will use the site settings it reads from nG1 server and
 will create a "current" CSV file.
Then it writes this "right now" dataframe out to a date-time stamped CSV file that replaces the "Current" CSV file.
Then the program compares the "current" dataframe to the "right now" dataframe to see if there are any changes.
If there are added sites, deleted sites or modified sites, this information will be written to "diff" CSV file.
The operator can examine the "diff" CSV file to understand what has changed since the last time this program ran.
Note: To connect to an nG1 server, you must first run the script cred_script_nG1.py. This is a menu-driven,
 interactive program that can run in a DOS command console or a MAC/Linux console.
After running that script, the ng1_site_getter.py can be run without any human interaction.
Note: For the case where you are running on a Linux server that does not have access to the internet, or you
 don't need the source code, there are binary versions of both programs in this repo that allow you to run
 it like a bash script (./), The version of python used, the python program, modules and all libraries needed
 are wrapped in. No dependencies needed. Just upload the binaries, chmod 777 to both filenames and run with ./
Any runtime info or errors are written to a date-time stamped log file created in the local directory.
This program was written by John Giles, NetScout SE. Initial version 0.1 created January 2021.
"""

# Disable the warnings for ignoring Self-Signed Certificates
requests.packages.urllib3.disable_warnings()

class Credentials:
    """
        A class to hold nG1 user credentials and other nG1 connection criteria.
        This is needed to make an API connection to nG1 and authenticate.
        ...
        Attributes
        ----------
        ng1hostname : str
            The hostname of the ng1 server.
        ng1port : str
            The port to use for the HTTP-HTTPS connection.
        ng1username : str
            The ng1 username for the connection.
        ng1password : str
            The encrypted ng1 password if using a password.
        ng1password_pl: str
            The unencrypted password for the connection.
        use_token : bool
            Use a token rather than a password for the connection.
        ng1token : str
            The encrypted token if using a token.
        ng1token_pl: str
            The decrypted ng1 token if using a token.
        ng1key : str
            The key contents of the private ng1key_file.
        expiry_time : str
            The number of seconds before the encrypted password or token expires.
        """
    def __init__(self):
        self.ng1hostname = ''
        self.ng1port = ''
        self.ng1username = ''
        self.ng1password = ''
        self.ng1password_pl = ''
        self.use_token = False
        self.ng1token = ''
        self.ng1token_pl = ''
        self.ng1key_file = ''
        self.pkey = ''
        self.expiry_time = ''

def create_logging_function():
    """Creates the logging function and specifies a log file to write to that is date-time stamped.
    :return: The logger instance if successfully completed, and the logging filename. Return False if not successful.
    """
    now = datetime.now()
    date_time = now.strftime("%Y_%m_%d_%H%M%S") # Used for timestamping filenames.
    log_filename = 'nG1_site_getter_' + date_time + '.log' #The name of the log file we will write to.

    try:
        # Call the basicConfig module and pass in the log file filename.
        logging.basicConfig(filename=log_filename, format='%(asctime)s %(message)s', filemode='a+')
        # Call the logging class and create a logger object.
        logger = logging.getLogger()
        # Set the logging level to the lowest setting so that all logging messages get logged.
        logger.setLevel(logging.INFO) # Allowable options include DEBUG, INFO, WARNING, ERROR, and CRITICAL.
        # Write the current date and time to the log file to at least show when the program was executed.
        logger.info(f"*** Start of logs {date_time} ***")
        return logger, log_filename
    except:
        return False

def get_decrypted_credentials(cred_filename, ng1key_file, logger):
    """Read in the encrypted user or user-token credentials from a local CredFile.ini file.
    Decrypt the credentials and place all the user credentials attributes into a creds instance.
    :cred_filename: A string that is the name of the cred_filename to read in.
    :ng1key_file: A string that is the name of the ng1's key file to read in.
    :return: If successful, return the creds as a class instance that contains all the params needed to
    connect to the ng1 server via HTTP or HTTPS and authenticate the user. Return False if any error occurrs.
    """
    # Create a creds instance to hold our user credentials.
    creds = Credentials()
    # Retrieve the decrypted credentials that we will use to open a session to the ng1 server.
    try:
        try: # Open the keyfile containing the key needed to decrypt the password.
            with open(ng1key_file, 'r') as ng1key_in:
                ng1key = ng1key_in.read().encode() # Read the key as a string.
                fng1 = Fernet(ng1key) # Create an instance of the Fernet class to hold the key info.
        except IOError as e: # Handle file I/O errors.
            print(f"\n[ERROR] Fatal error: Unable to open ng1key file: {ng1key_file}")
            print('Did you run the cred_script_nG1.py first?')
            logger.critical(f"[ERROR] Fatal error: Unable to open ng1key file: {ng1key_file}")
            logger.error(f'[ERROR] I/O error({e.errno}):  {e.strerror}.')
        except Exception as e:
            logger.exception(f"[ERROR] Fatal error: Unable to open ng1key_file: {ng1key_file}")
            logger.exception(f"Exception error is:\n{e}")
            return False
        with open(cred_filename, 'r') as cred_in:
            lines = cred_in.readlines()
            creds.ng1token = lines[4].partition('=')[2].rstrip("\n")
            #Check to see if we are expected to use an API Token or Username:Password
            # print(f' creds.ng1token is: {creds.ng1token}')
            if len(creds.ng1token) > 1: # Yes use a Token rather than a password.
                creds.use_token = True
                creds.ng1token_pl = fng1.decrypt(creds.ng1token.encode()).decode() # Use the key to decrypt.
                creds.ng1username = lines[2].partition('=')[2].rstrip("\n")
            else:
                creds.use_token = False # No, do not use a Token, but rather use a password.
                creds.ng1username = lines[2].partition('=')[2].rstrip("\n")
                creds.ng1password = lines[3].partition('=')[2].rstrip("\n")
                creds.ng1password_pl = fng1.decrypt(creds.ng1password.encode()).decode() # Use the key to decrypt.
            creds.ng1hostname = lines[1].partition('=')[2].rstrip("\n")
            creds.ng1Port = lines[5].partition('=')[2].rstrip("\n")
    except IOError as e: # Handle file I/O errors.
        logger.error(f"[ERROR] Fatal error: Unable to open cred_filename: {cred_filename}")
        logger.error(f'[ERROR] I/O error({e.errno}):  {e.strerror}.')
        return False
    except Exception as e: # Handle other unexpected errors.
        logger.exception(f"[ERROR] Fatal error: Unable to open cred_filename: {cred_filename}")
        logger.exception(f"[ERROR] Exception error is:\n{e}")
        return False

    return creds # The function was successful.

def determine_ng1_api_params(creds, logger):
    """Based on the values in the creds instance, determine what all the nG1 API connection parameters are.
    :creds: A class instance that holds all our nG1 connection and user authentication credentials values.
    :logger: An instance of the logger class so we can write error messages if they occur.
    :return: If successful, return the values for ng1_host, headers, cookies and credentials.
    Return False if any error occurrs.
    """
    # You can use an authentication token named NSSESSIONID obtained from the User Management module in nGeniusONE (open the user and click Generate New Key).
    # This token can be passed to nG1 as a cookie so that we can autheticate.
    # If we are using the token rather than credentials, we will set credentials to 'Null'.
    # If we are using the username:password rather than a token, we will set cookies to 'Null'.
    # Initialize the return parameters just in case we have an error and need to return False.
    ng1_host = False
    headers = ''
    cookies = ''
    credentials = ''

    try:
        if creds.use_token == True:
            credentials = 'Null'
            cookies = {'NSSESSIONID': creds.ng1token_pl} # In this case we will use the token read from the CredFile.ini file.
        # Otherwise set the credentials to username:password and use that instead of an API token to authenticate to nG1.
        else:
            cookies = 'Null'
            credentials = creds.ng1username + ':' + creds.ng1password_pl # Combines the username and the decrypted password.

        # set the URL web protocol to match what was read out of the CredFile.ini file for ng1Port.
        if creds.ng1Port == '80' or creds.ng1Port == '8080':
            web_protocol = 'http://'
        elif creds.ng1Port == '443' or creds.ng1Port == '8443':
            web_protocol = 'https://'
        else:
            print(f'[CRITICAL] nG1 destination port {creds.ng1Port} is not equal to 80, 8080, 443 or 8443')
            logger.critical(f'[CRITICAL] nG1 destination port {creds.ng1Port} is not equal to 80, 8080, 443 or 8443')
            return ng1_host, headers, cookies, credentials # As we are returning multiple params, we will use ng1_host to set True or False.
        # Build up the base URL to use for all nG1 API calls.
        ng1_host = web_protocol + creds.ng1hostname + ':' + creds.ng1Port

        # Hardcoding the HTTP header to use in all the nG1 API calls. Specifies JSON data type.
        headers = {
            'Cache-Control': "no-cache",
            'Accept': "application/json",
            'Content-Type': "application/json"
        }
    except Exception as e:
        logger.exception(f"[ERROR] Fatal error: Unable to create log file function for: {log_filename}")
        logger.exception(f"[ERROR] Exception error is:\n{e}")
        ng1_host = False
        return ng1_host, headers, cookies, credentials

    return ng1_host, headers, cookies, credentials

def open_session(ng1_host, headers, cookies, credentials, logger):
    """Open an HTTP or HTTPS API session to the nG1. Reuse that session for all commands until finished.
    :ng1_host: The hostname or IP address of the nG1 server.
    :headers: The HTTP header to use for all nG1 API calls. Specifies JSON format.
    :cookies: The initial cookie to use that contains the 'NSSESSIONID' decrypted token, if using a token, else 'Null' if using a password.
    :credentials: The combination of the username:password if using a password, else 'Null' if using a token.
    :logger: An instance of the logger object to write to in case of an error.
    :return: If successful, return the session cookie to be used for every API call. This allows the reuse of the session.
    return False if there are any errors or exceptions.
    """
    uri = "/ng1api/rest-sessions" # The uri to use for nG1 API initial connection.
    url = ng1_host + uri

    # Perform the HTTP or HTTPS API call to open the session with nG1 and return a session cookie.
    try:
        if credentials == 'Null': # Use a token rather than username:password.
            # Null credentials tells us to use the token. We will use this post and pass in the cookies as the token.
            post = requests.request("POST", url, headers=headers, verify=False, cookies=cookies)
        elif cookies == 'Null': # Use a username:password credentials combo instead of a token.
            #split the credentials string into two parts; username and the unencrypted password.
            ng1username = credentials.split(':')[0]
            ng1password_pl = credentials.split(':')[1]
            # Null cookies tells us to use the credentials string. We will use this post and pass in the credentials string.
            post = requests.request("POST", url, headers=headers, verify=False, auth=(ng1username, ng1password_pl))
        else:
            # print(f'[CRITICAL] opening session to URL: {url} failed')
            logger.critical(f'[CRITICAL] opening session to URL: {url} failed.')
            # print('Unable to determine authentication by credentials or token')
            logger.critical('[CRITICAL] Unable to determine authentication by credentials or token.')
            return False
        if post.status_code == 200: # The nG1 API call was successful.
            print(f'[INFO] Opened Session to URL: {url} Successfully')
            logger.info(f'[INFO] Opened Session to URL: {url} Successfully')
            # Utilize the returned cookie for future authentication. Keep this session open for all nG1 API calls.
            cookies = post.cookies
            return cookies # Success! Return the session cookie so it can be used for subsequent API calls.
        else: # We reached the nG1, but the request has failed. A different HTTP code other than 200 was returned.
            logger.critical(f'[CRITICAL] opening session to URL: {url} failed. Response Code: {post.status_code}. Response Body: {post.text}.')
            return False
    except Exception as e: # This means we likely did not reach the nG1 at all. Check your VPN or internet connection.
        logger.critical(f'[CRITICAL] Opening the nG1 API session has failed')
        logger.critical(f'[CRITICAL] Cannot reach URL: {url}')
        logger.critical(f'[CRITICAL] Check the VPN or internet connection')
        logger.exception(f"[ERROR] Exception error is:\n{e}")
        return False

def close_session(ng1_host, headers, cookies, logger):
    """Close the HTTP or HTTPS API session to the nG1.
    :ng1_host: The hostname or IP address of the nG1 server.
    :headers: The HTTP header to use for all nG1 API calls. Specifies JSON format.
    :cookies: The session cookie to use for all repeated queries to the nG1 API.
    :logger: An instance of the logger object to write to in case of an error.
    :return: If successful, return True. Return False if there are any errors or exceptions.
    """
    try:
        uri = "/ng1api/rest-sessions/close"
        url = ng1_host + uri
        # perform the HTTPS API call
        close = requests.request("POST", url, headers=headers, verify=False, cookies=cookies)

        if close.status_code == 200: # The nG1 API call was successful.
            print('[INFO] Closed nG1 API Session Successfully')
            logger.info('[INFO] Closed nG1 API Session Successfully')
            return True # Success! We closed the API session.
        else: # The nG1 API call failed.
            logger.error(f'[ERROR] closing session failed. Response Code: {close.status_code}. Response Body: {close.text}.')
            return False
    except Exception as e:
        # This means we likely did not reach the nG1 at all. Check your VPN or internet connection.
        logger.critical(f'[CRITICAL] Closing the nG1 API session has failed')
        logger.exception(f"Exception error is:\n{e}")
        print('[CRITICAL] Closing the nG1 API session has failed')
        print('We did not reach the nG1. Check your VPN or internect connection')
        return False

def write_device_interfaces_config_to_csv(devices_dict, logger):
    """Write the device and interface data to a CSV file using a json dictionary.
    :devices_dict: The dictionary of device + device interface data collected.
    :logger: An instance of the logger object to write to in case of an error.
    :return: True if successful. Return False if there are any errors or exceptions.
    """
    now = datetime.now()
    date_time = now.strftime("%Y_%m_%d_%H%M%S") # Used for timestamping filenames.
    filename = 'nG1_get_all_interfaces_' + str(date_time) + '.csv' # Assemble the CSV filename string.
    try:
        with open(filename,'w', encoding='utf-8', newline='') as f:
            fieldnames = ['Infinistream', 'interfaceName', 'alias', 'interfaceNumber', 'portSpeed', 'interfaceSpeed', 'status', 'alarmTemplateName', 'virtulization', 'activeInterfaces', 'inactiveInterfaces', 'interfaceLinkType', 'nBAnASMonitoring']
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            # Write the first row as a header that includes names for each column as specified by fieldnames above.
            writer.writeheader()
            for device in devices_dict:
                # Pull the list of interfaces out of the devices dictionary for the device we are looping on now.
                interfaces_list = devices_dict[device]
                # Write each interface for this one device as a row in the CSV file.
                for interface in interfaces_list:
                    # Add the name of the Infinistream to this row.
                    interface['Infinistream'] = device
                    writer.writerow(interface)
            print(f'[INFO] Writing Device Interfaces to CSV file: {filename} was Successful')
            logger.info(f'[INFO] Writing Device Interfaces to CSV file: {filename} was Successful')
            return True # Success!
    except IOError as e:
        logger.error(f'[ERROR] Unable to write Interface Locations to the CSV file: {filename}')
        logger.error(f'[ERROR] I/O error({e.errno}):  {e.strerror}.')
        return False
    except Exception as e: # Handle other exceptions such as attribute errors.
        logger.error(f'[ERROR] Unable to write Interface Locations to the CSV file: {filename}')
        logger.exception(f"Exception error is:\n{e}")
        return False

def get_sites(ng1_host, headers, cookies, logger):
    """Use the nG1 API to get all the config info on all sites in the system.
    :ng1_host: The hostname or IP address of the nG1 server.
    :headers: The HTTP header to use for all nG1 API calls. Specifies JSON format.
    :cookies: The session cookie to use for all repeated queries to the nG1 API.
    :logger: An instance of the logger object to write to in case of an error.
    :return: If successful, return the sites info in JSON format.
    Return False if there are any errors or exceptions.
    """
    uri = "/ng1api/ncm/sites/"
    url = ng1_host + uri
    try:
        # perform the HTTPS API call to get the sites information
        get = requests.get(url, headers=headers, verify=False, cookies=cookies)

        if get.status_code == 200:
            # success
            print('[INFO] get_sites nG1 API request Successful')
            logger.info('[INFO] get_sites nG1 API request Successful')
            # return the json object that contains the site information
            return get.json()
        else:
            logger.error(f'[ERROR] get_sites nG1 API request failed. Response Code: {get.status_code}. Response Body: {get.text}.')
            return False
    except Exception as e: # Handle other unexpected errors.
        logger.exception('[ERROR] get_sites nG1 API request failed')
        logger.exception(f'[ERROR] URL sent is: {url}')
        logger.exception(f"[ERROR] Exception error is:\n{e}")
        return False

def convert_json_dict_to_dataframe(config_data):
    """Convert a nested python dictionary into a pandas dataframe.
    :config_data: The dictionary that holds the configuration data we extracted from nG1.
    :return: Return status = True and the "right now" pandas dataframe if successful.
    Return status = False and an empty dataframe if there are any errors or exceptions.
    """
    try:
        # Initialize an empty list to hold the per-interface data.
        rows = []
        status = True # Tells the calling function if we were successful in the conversion.
        for key in config_data: # Iterate through each key in the dictionary.
            config_items_rows = config_data[key] # Pull out the list of configs from the parent key.
            for item in config_items_rows: # Iterate through each config item as they will be the rows in our dataframe.
                rows.append(item) # Appending the config item row to the 'rows' list to produce a flat dataset.
        # Put the flat list of config items rows into a pandas dataframe.
        df_right_now = pd.DataFrame(rows)
        df_right_now = df_right_now[['id','name', 'addresses', 'speedKbps']] # reorder the columns.
        # Pandas dataframes don't have types of 'list' or 'dict', so we need to convert any of these to strings.
        df_right_now['addresses'] = df_right_now.addresses.astype('str') # Cast the list of ipaddress ranges into a string.
        #df_right_now.set_index('id', inplace=True) # Set the id column as the dataframe index.

        return status, df_right_now # You can't have a whole dataframe be either True or False. So we add a status boolean.
    except Exception as e:
        logger.exception(f'[ERROR] Conversion of config data to dataframe has failed')
        logger.exception(f"Exception error is:\n{e}")
        status = False
        df_right_now = ''
        return status, df_right_now

def write_dataframe_to_csv(df, csv_filename, logger):
    """Write the device and interface dataframe to a CSV file.
    :df: The dataframe of nG1 config data collected.
    :csv_filename: The name of the CSV file to write to.
    :logger: An instance of the logger object to write to in case of an error.
    :return: If successful, return True. Return False if there are any errors or exceptions.
    """
    try:
        df.to_csv(csv_filename, header=True, encoding='utf-8', index=False) # Write the dataframe to the CSV file.
    except PermissionError as e:
        logger.exception(f'[ERROR] Permission Error: Write dataframe to CSV file: {csv_filename}')
        logger.exception(f'[ERROR] Permission Error({e.errno}):  {e.strerror}.')
        print(f'[ERROR] Conversion of CSV file: {config_current_csv} to a dataframe has failed')
        print('Do you have the file open?')
        status = False
        config_current_is_found = False
        current_df = ''
        return status, config_current_is_found, current_df
    except IOError as e: # Handle file I/O errors.
        print(f'\n[ERROR] I/O error: Write dataframe to CSV file: {csv_filename}')
        logger.critical(f'[ERROR] I/O Error: Write dataframe to CSV file: {csv_filename}')
        logger.error(f'[ERROR] I/O Error({e.errno}):  {e.strerror}.')
    except Exception as e:
        logger.exception(f'[ERROR] Write dataframe to CSV file: {csv_filename} has failed"')
        logger.exception(f'[ERROR] Exception error is:\n{e}')
        return False

    return True

def backup_current_CSV(config_current_csv, config_archive_csv, logger):
    """If this program has run before, there will be a "current" copy of the site configuration CSV File.
    If found in the local directory, read it into a pandas dataframe for comparison later.
    If found in the local directory, rename it to "archive" with a time-date stamp.
    :config_current_csv: A string. The CSV filename of the current config created at the last run of this program.
    :config_archive_csv: A string. The CSV filename of the backup we will create if a "current" csv file exists.
    :logger: An instance of the logger object to write to in case of an error.
    :return: If successful, return status = True and the current pandas dataframe.
    Return config_current_is_found = True is the "current" CSV file is found, or False if the file is not found.
    Return status = False and an empty pandas dataframe if there are any errors or exceptions.
    """
    now = datetime.now()
    date_time = now.strftime("%Y_%m_%d_%H%M%S") # Used for timestamping filenames.
    try:
        # if config_current_csv exists read in as a pandas df, rename and cp current to archive then return the current df.
        if os.path.isfile(config_current_csv):
            current_df = pd.read_csv(config_current_csv)
            #print(f'\nCurrent df is: \n{current_df}')
            #print(f'dtypes are: \n{current_df.dtypes}')
            # Pandas dataframes don't have types of 'list' or 'dict', so we need to convert any of these to strings.
            current_df['addresses'] = current_df.addresses.astype('str') # Cast the list of ipaddress ranges into a string.
            config_archive_csv = config_archive_csv + '_' + str(date_time) + '.csv'
            current_df = current_df[['id','name', 'addresses', 'speedKbps']] # reorder the columns.
            os.rename(config_current_csv, config_archive_csv)
            print(f"[INFO] Backing up file {config_current_csv} to {config_archive_csv} Successful")
            logger.info(f"[INFO] Backing up file {config_current_csv} to {config_archive_csv} Successful")
            config_current_is_found = True
            status = True
            return status, config_current_is_found, current_df
        else:
            config_current_is_found = False
            status = True
            current_df = ''
            return status, config_current_is_found, current_df
    except PermissionError as e:
        logger.exception(f'[ERROR] Conversion of CSV file: {config_current_csv} to a dataframe has failed')
        logger.exception(f"[ERROR] Exception error is:\n{e}")
        print(f'[ERROR] Conversion of CSV file: {config_current_csv} to a dataframe has failed')
        print('Do you have the file open?')
        status = False
        config_current_is_found = False
        current_df = ''
        return status, config_current_is_found, current_df
    except Exception as e: # An error has occurred, log the error and return a status of False.
        logger.exception(f'[ERROR] Conversion of config data to dataframe has failed')
        logger.exception(f"[ERROR] Exception error is:\n{e}")
        status = False
        config_current_is_found = False
        current_df = ''
        return status, config_current_is_found, current_df

def modifiedRows(dfLeft, dfRight, logger):
    """This function takes in two pandas dataframes and determines if there are any config items
     that have been modified since the last time this program was run. A new dataframe (dfModifiedRows)
      is created that includes all rows for all possible cases; NoChange, *Added, *Deleted or *Modified.
      A new column (_Change) is appended to the dataframe to indicate the type of change that occurred.
    :dfLeft: A pandas dataframe. The 'current' set of config data from the previous program execution.
    :dfRight: A pandas dataframe. The 'right now' set of config data from the nG1 API call we just made.
    :logger: An instance of the logger object to write to in case of an error.
    :return: If successful, return status = True and the dfModifiedRows pandas dataframe.
    Return status = False and an empty pandas dataframe if there are any errors or exceptions.
    """
    try:
        dfMerged = dfLeft.merge(dfRight, indicator=True, how='outer')
        # Convert '_merge' indicator column into a situation specific descriptive column:
        # left_only / right_only indicates a change to a config setting if the id and name values match.
        # - Keep the left value.
        # both, indicates no change to this config setting since last time the program was ran.
        # left_only (no matching id, name) indicates a config setting was deleted.
        # right_only (no matching user id) indicates a config setting was added.
        grp_cols = ['id', 'name']
        step1DF = dfMerged.groupby(grp_cols).filter(lambda x: x.addresses.count() > 1)[dfMerged.groupby(grp_cols).filter(lambda x: x.addresses.count() > 1)['_merge'] == 'left_only']
        step1DF['_merge'].astype('object') # convert from categorical back to object
        step1DF['_merge'] = '*Mod_Orig'
        #print(f"\nstep1DF is: \n{step1DF}")
        step2DF = dfMerged.groupby(grp_cols).filter(lambda x: x.addresses.count() > 1)[dfMerged.groupby(grp_cols).filter(lambda x: x.addresses.count() > 1)['_merge'] == 'right_only']
        step2DF['_merge'].astype('object') # convert from categorical back to object
        step2DF['_merge'] = '*Mod_New'
        #print(f"\nstep2DF is: \n{step2DF}")
        dfChanges_orig_new = pd.concat([step1DF, step2DF])
        #print(f"\ndfChanges_orig_new: \n{dfChanges_orig_new}")
        describers = {'_merge':{'both': 'No_Change', 'left_only':'*Deleted', 'right_only':'*Added'}}
        step3DF = dfMerged.groupby(grp_cols).filter(lambda x: x.addresses.count() == 1).replace(describers)
        #print(f"\nstep3DF is: \n{step3DF}")
        dfModifiedRows = pd.concat([dfChanges_orig_new, step3DF])
        dfModifiedRows.rename(columns={'_merge': '_Change'}, inplace=True)
        dfModifiedRows.sort_index(inplace=True)
        dfModifiedRows = dfModifiedRows[['id','name', 'addresses', 'speedKbps', '_Change']]
        #print(f"\ndfModifiedRows after sort and rename index is: \n{dfModifiedRows}")
        status = True
        return status, dfModifiedRows
    except Exception as e: # An error has occurred, log the error and return a status of False.
        logger.exception(f'[ERROR] The check for modified config items has failed')
        logger.exception(f"[ERROR] Exception error is:\n{e}")
        status = False
        dfModifiedRows = ''
        return status, dfModifiedRows

def get_config_data_differences(current_df, right_now_df, logger):
    """This function takes in two pandas dataframes and determines if there are any config items
     that have been added, removed (deleted) or modified since the last time this program was run.
    :dfLeft: A pandas dataframe. The 'current' set of config data from the previous program execution.
    :dfRight: A pandas dataframe. The 'right now' set of config data from the nG1 API call we just made.
    :logger: An instance of the logger object to write to in case of an error.
    :return: If successful, return status = True and the diff_df pandas dataframe.
    Return status = False and an empty pandas dataframe if there are any errors or exceptions.
    """
    diff_df = ''
    try:
        status, dfModifiedRows = modifiedRows(current_df, right_now_df, logger)
        if status == False: # Determining the modified config items has failed.
            did_anything_change = False
            diff_df = ''
            return status, did_anything_change, diff_df
        did_anything_change = dfModifiedRows._Change.isin(['*Mod_Orig', '*Mod_new', '*Added', '*Deleted']).any().any()
        if did_anything_change == False:
            print('[INFO] No differences found between the site configuration right now versus the last time the program ran')
            logger.info('[INFO] No differences found between the site configuration right now versus the last time the program ran')
            diff_df = ''
            status = True
            return status, did_anything_change, diff_df # Success. Return the status as True (no errors) and an empty diff_df dataframe.
        else:
            print('[INFO] Differences have been found between the site configuration right now versus the last time the program ran')
            print('[INFO] Please review the change_log CSV file')
            logger.info('[INFO] Differences have been found between the site configuration right now versus the last time the program ran')
            diff_df = dfModifiedRows
            status = True
            return status, did_anything_change, diff_df # Success. Return the status as True (no errors) and an empty diff_df dataframe.
    except Exception as e: # An error has occurred, log the error and return a status of False.
        logger.exception(f'[ERROR] The check for config differences from the last time the program ran has failed')
        logger.exception(f"[ERROR] Exception error is:\n{e}")
        status = False
        did_anything_change = False
        diff_df = ''
        return status, did_anything_change, diff_df

def flags_and_arguments(prog_version):
    try:
        # Create an instance of the parser and add arguments.
        parser = argparse.ArgumentParser()
        parser.add_argument('-set', action="store_true", help='set the nG1 config to match the xxxx_config_current.csv', dest='set', default=False)
        parser.add_argument("-V", "--version", action="store_true", help="show program version and exit", dest='version', default=False)
        # Parse the arguments and create a result.
        args = parser.parse_args()
        if args.version == True: # They typed either "-V" or "--version" flags.
            print(f'Program version is: {prog_version}')
            sys.exit()
        if args.set == True: # They typed the "-set" flag.
            is_set_config_true = True # I need to do a get and a set operation.
        else:
            is_set_config_true = False # I only need to do a get operation.
        status = True

        return status, is_set_config_true
    except Exception as e: # An error has occurred, log the error and return a status of False.
        logger.exception(f'[ERROR] Parsing the arguments has failed')
        logger.exception(f"[ERROR] Exception error is:\n{e}")
        status = False
        is_set_config_true = False

        return status, is_set_config_true
# -----------------------------------------------------------------------------------------------------------------
def main():
    prog_version = '0.1'
    status, is_set_config_true = flags_and_arguments(prog_version)
    if statys == False: # Parsing the user entered flags or arguments has failed Exit.
        print("\n[CRITICAL] Main, Parsing the user entered flags or arguments has failed")
        print('Exiting...')
        sys.exit()

    # Create a logger instance and write the starting date_time to a log file.
    logger, log_filename = create_logging_function()
    if logger == False: # Creating the logger instance has failed. Exit.
        print("\n[CRITICAL] Main, Creating the logger instance has failed")
        print('Exiting...')
        sys.exit()

    # Hardcoding the name of the "current" CSV file that holds the site config data from the last run.
    config_current_csv = 'site_config_current.csv'
    # Hardcoding the name of the "archive" CSV file that we will use to backup the "current" CSV file.
    config_archive_csv = 'site_config_archive' # No extention as we will append a time-date + .csv to the name.
    # Hardcoding the name of the "change_log" CSV file that we will use to output and differences seen since last program execution.
    change_log_csv = 'change_log.csv' # No extention as we will append a time-date + .csv to the name.

    # Hardcoding the filenames for encrypted credentials and the key file needed to decrypt the credentials.
    cred_filename = 'CredFile.ini'
    os_type = sys.platform
    if os_type == 'linux':
        ng1key_file = '.ng1key.key' # hide the probekey file if Linux.
    else:
        ng1key_file = 'ng1key.key' # don't hide it if Windows.

    # Get the user's credentials from a file and decrypt them.
    creds = get_decrypted_credentials(cred_filename, ng1key_file, logger)
    if creds == False: # Creating the creds instance has failed. Exit.
        logger.critical(f"[CRITICAL] Main, Getting the login credentials from file: {cred_filename} failed")
        print(f"\n[CRITICAL] Main, Getting the ng1 login credentials from file: {cred_filename} failed")
        print(f'Check the log file: {log_filename}. Exiting...')
        sys.exit()

    # Based on what is in the creds, determine all the parameters needed to make an nG1 API connection.
    ng1_host, headers, cookies, credentials = determine_ng1_api_params(creds, logger)
    if ng1_host == False: # Determining the nG1 API parameters has failed. Exit.
        logger.critical(f"[CRITICAL] Main, determining the nG1 API parameters has failed")
        print(f"\n[CRITICAL] Main, determining the nG1 API parameters has failed")
        print(f'Check the log file: {log_filename}. Exiting...')
        sys.exit()

    # Open an API session to nG1 and keep it open for all subsequent calls.
    cookies = open_session(ng1_host, headers, cookies, credentials, logger)
    if cookies == False: # Opening the HTTP-HTTPS nG1 API session has failed. Exit.
        logger.critical(f"[CRITICAL] Main, opening the HTTP-HTTPS nG1 API session has failed")
        print(f"\n[CRITICAL] Main, opening the HTTP-HTTPS nG1 API session has failed")
        print(f'Check the log file: {log_filename}. Exiting...')
        sys.exit()

    # Backup the current configuration CSV created the last time this program ran (rename it if it exists).
    status, config_current_is_found, current_df = backup_current_CSV(config_current_csv, config_archive_csv, logger)
    if status == False: # Backing up the current CSV config file has failed.
        logger.critical(f"[CRITICAL] Main, backup_current_csv has failed")
        print(f"\n[CRITICAL] Main, backup_current_csv has failed")
        print(f'Check the log file: {log_filename}. Exiting...')
        sys.exit()

    # Get congig info on all sites from the nG1 API. Returned as a python object (a json formatted dictionary).
    config_data = get_sites(ng1_host, headers, cookies, logger)
    if config_data == False: # Getting the sites data from the nG1 API has failed. Exit.
        logger.critical(f"[CRITICAL] Main, getting the sites data from the nG1 API has failed")
        print(f"\n[CRITICAL] Main, getting the sites data from the nG1 API has failed")
        print(f'Check the log file: {log_filename}. Exiting...')
        sys.exit()

    # Convert the json nested dictionary to a flatend dataframe in pandas.
    status, right_now_df = convert_json_dict_to_dataframe(config_data)
    if status == False: # The conversion has failed. Exit.
        logger.critical(f"[CRITICAL] Main, dataframe conversion has failed")
        print(f"\n[CRITICAL] Main, dataframe conversion has failed")
        print(f'Check the log file: {log_filename}. Exiting...')
        sys.exit()

    # Write the "right now" pandas dataframe to a CSV file.
    status = write_dataframe_to_csv(right_now_df, config_current_csv, logger)
    if status == False: # The write dataframe to CSV file operation has failed. Exit.
        logger.critical(f"[CRITICAL] Main, write_dataframe_to_csv to CSV file: {config_current_csv} has failed")
        print(f"\n[CRITICAL] Main, writing the sites dataframe to CSV file: {config_current_csv} has failed")
        print(f'Check the log file: {log_filename}. Exiting...')
        sys.exit()

    if config_current_is_found is True: # A 'current' CSV was found. Compare the previous config data to 'right now'.
        status, did_anything_change, diff_df = get_config_data_differences(current_df, right_now_df, logger)
        if status == False: # The get config data differences has failed.
            logger.critical(f"[CRITICAL] Main, get_config_data_differences has failed")
            print(f"\n[CRITICAL] Main, get_config_data_differences has failed")
            print(f'Check the log file: {log_filename}. Exiting...')
            sys.exit()
        if did_anything_change == True: # Changes have been found in site config setting since last program execution.
            # Write the "diff_df" pandas dataframe to a CSV file.
            status = write_dataframe_to_csv(diff_df, change_log_csv, logger)
            if status == False: # The write dataframe to CSV file operation has failed. Exit.
                logger.critical(f"[CRITICAL] Main, write_dataframe_to_csv to CSV filename: {change_log_csv} has failed")
                print(f"\n[CRITICAL] Main, writing the differences dataframe to CSV file: {change_log_csv} has failed")
                print(f'Check the log file: {log_filename}. Exiting...')
                sys.exit()

    # We are all finished, close the nG1 API session.
    if close_session(ng1_host, headers, cookies, logger) == False: # Failed to close the API session.
        logger.critical(f"[CRITICAL] Main, close_session has failed")
        print(f"\n[CRITICAL] Main, Unable to close the nG1 API session")
        print(f'Check the log file: {log_filename}. Exiting...')
        sys.exit()

    print(f'[iNFO] The CSV file: {config_current_csv} was created at {time.ctime()}')
    logger.info(f'[INFO] The CSV file: {config_current_csv} was created at {time.ctime()}')
    print('[INFO] Program execution has completed Successfully')
    logger.info('[INFO] Program execution has completed Successfully')

if __name__ == "__main__":
    main()
