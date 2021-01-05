# ng1_site_getter
Python3 code to create an API connection to an nGeniusONE server, authenticate, get the site config, write it to CSV.

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
