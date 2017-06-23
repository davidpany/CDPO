#!/usr/bin/env python

"""
Copyright 2017 David Pany (@DavidPany)

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.


Card Data Processor and Organizer (CDPO)
Version 1.0 - 2017-06-23 (SANS DFIR Summit Edition)

    CDPO is a tool to validate, de-duplicate, combine, query, and encrypt track data recovered from a breach

Created by David Pany - 2017
twitter: @davidpany
github: https://github.com/davidpany

Encryption implemented  by Patrick Charbonneau
"""

from __future__ import print_function #Used for hipster print function
import sqlite3 # used to interact with sqlite DB
import sys  # used to quit if user does not make decision about duplicate .sqlite files.
import cmd  # used for cli loop
import os   # used to import files
import fnmatch # used to match filenames and wildcards for importing
import re   # used for track regex
import time # used to track time of imports and to find current MMYY
import getpass # used to get password without echo
import hashlib # used to MD5 password for verification
import base64 # used to convert encrypted PANs to strings for DB storage
import datetime # used to create unique statsCSV and DB filenames
import csv # used to write output files
import json # read json strings from the db and convert to dicts

"""
ToDo
    [ ]After sanitizing collection name, check to see if the sanitized name exists already
    [ ]Add speedygonzales from Brandan Schondorfer
    [ ]Format the available collections when making a super so they look nice
    [ ]Change file command to use csv module
    [ ]Add tab-complete for import, combine, query, etc.
    [ ]Add BINLIST ranger post processor
    [ ]Add status updates to query table creations
    [ ]Don't make a database table for files that don't have valid track data
    [ ]Add support to read in a file of only pan (no full track data)
        [ ]requires an additional DB field for P on top of 1, 2, and 12; and maybe EXP date filler of 9999 or null?
    [ ]If wildcard used for input, limit display noise or consider using buffer to keep it clean
    [ ]Format components part of stats output
    [ ]Add option to delete a collection DB table and from the metadata table
"""

SPECIAL_CHARS_LIST = ["`", "~", "!", "@", "#", "$", "%", "^", "&", "*", "(", ")", "-", "=", "+", "\\", "|", ";", ":",
                      "'", '"', ",", "<", ".", ">", "/", "?", " ", "[", "]", "{", "}"]

################################################### CMD Loop Class ####################################################
class CDPO(cmd.Cmd):
    """\tFramework for counting PCI records"""
    def __init__(self):
        cmd.Cmd.__init__(self)
        self.db_file_name, self.metadata, self.skrtkey = initialize()

    # Define settings
    prompt = "(CDPO): "
    intro = "\n   Hello, I am CDPO, PCI track data relations. How might I serve you?.\n\tTry 'help'\n"

    def do_import(self, track_file_args):
        """\timport [track_file]
        \tImport the specified file. Wildcards and directory traversal are supported.\n\
        \tCDPO ignores .py and .sqlite files.\n"""
        print()

        if track_file_args:
            if "\\" in track_file_args:
                track_file_args = track_file_args.replace("\\", "/")
            if "/" in track_file_args:
                target_path = track_file_args.rpartition("/")
            else:
                target_path = "./", "", track_file_args

            directory = target_path[0]
            file_name = target_path[2]

            files_to_import = []
            for root, dir_name, file_names in os.walk(directory):
                for file_name in fnmatch.filter(file_names, file_name):
                    file_path = os.path.join(root, file_name).replace("\\", "/")
                    if file_path[-3:] != ".py" and  file_path[-7:] != ".sqlite":
                        files_to_import.append(file_path)

            if files_to_import:
                for track_file in files_to_import:

                    #Sanitize the file_name to match that the format of the DB Table names
                    temp_file_name = track_file.rpartition("/")[2]
                    if temp_file_name[0] in ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9"]:
                        temp_file_name = "_{}".format(temp_file_name)
                    if [char for char in SPECIAL_CHARS_LIST if char in temp_file_name]:
                        for special_char in SPECIAL_CHARS_LIST:
                            temp_file_name = temp_file_name.replace("{}".format(special_char), "_")

                    #Check to see if the imported file exists. Import if not, skip if exists
                    if temp_file_name not in read_all_collection_names(self.db_file_name, "list"):
                        print("   A while this may take. Patience you must have.")
                        create_collection(self.db_file_name, track_file, self.skrtkey)
                    else:
                        print("\tYou cannot add {} twice!\n".format(track_file))
            else:
                print("\tPlease speficy a valid file/files to import.\n\t  If you are traversing directories on"
                      "Windows, be sure to use a backslash \\ .\n\t  You may also use * wildcards.\n")
        else:
            print("\tPlease specify a file.\n")

    def do_show(self, default=None):
        """\tDisplays all collections loaded into CDPO and basic statistics\n"""
        conn = sqlite3.connect(self.db_file_name)
        c = conn.cursor()

        #Read all collection rows from metadata TABLE
        c.execute('SELECT * FROM metadata WHERE collection_type="collection"')
        collection_list = c.fetchall()
        print_loaded(collection_list, "Collections")

        c.execute('SELECT * FROM metadata WHERE collection_type="Super"')
        super_collection_list = c.fetchall()
        print_loaded(super_collection_list, "Super Collections")

        c.execute('SELECT * FROM metadata WHERE collection_type LIKE "Query%"')
        super_collection_list = c.fetchall()
        print_loaded(super_collection_list, "Query results")

        conn.close()

    def do_csvstats(self, garbage):
        """\tWrites basic statistics of all collections to a CSV file named show-CSV.csv\n"""
        conn = sqlite3.connect(self.db_file_name)
        c = conn.cursor()

        #Read all collection rows from metadata TABLE
        c.execute('SELECT * FROM metadata WHERE collection_type="collection"')
        collection_list = c.fetchall()

        c.execute('SELECT * FROM metadata WHERE collection_type="Super"')
        super_collection_list = c.fetchall()

        c.execute('SELECT * FROM metadata WHERE collection_type LIKE "Query%"')
        query_collection_list = c.fetchall()

        write_stats_to_csv(collection_list, super_collection_list, query_collection_list)

        conn.close()

    def do_combine(self, combo_name):
        """\tcombine [SuperCollection Name]
        \t\tCombine and de-duplicate two or more existing Collections into [SuperCollection Name]\n"""
        if combo_name:
            if combo_name.upper() != "ALL":
                combo_name = combo_name.replace(" ", "_") #prevents having super collection labels from having spaces
                all_collections_string = read_all_collection_names(self.db_file_name, "string")

                if combo_name not in all_collections_string:
                    combo_name = sanitize_collection_name(combo_name, combo_name)

                    print(" Please specify two or more existing collections to combine. (collection1 collection2)")
                    print(" Note that ALL will combine all loaded collections. Your choices are:")
                    print("\tALL {}\n".format(all_collections_string))
                    collections_to_add = ask_for_collections(all_collections_string)

                    if collections_to_add:

                        print("   A very, very long time this may take. Patience you must have.")
                        if collections_to_add == "ALL":
                            conn = sqlite3.connect(self.db_file_name)
                            c = conn.cursor()

                            c.execute('SELECT collection_name FROM metadata Where collection_type="collection"')
                            collection_list = c.fetchall()
                            collections_to_add = []
                            for collection_name in collection_list:
                                collections_to_add.append(str(collection_name[0]))

                        create_super(self.db_file_name, collections_to_add, combo_name)
                else:
                    print("\tIt looks like this Super Combination name is already used. Please try a different name.")
            else:
                print("\tYou cannot name your new super collection 'all'."
                      "Sorry about that but maybe try 'total' instead?\n")
        else:
            print("\tYou need to specify a new name for a new super collection.\n")

    def do_stat(self, existing_collection):###############
        """\tstat [collection]
        \t\tDisplay brand, track, Expiration Dates, and pan Count Statistics for one [collection]\n"""

        if existing_collection and existing_collection in read_all_collection_names(self.db_file_name, "list"):

            conn = sqlite3.connect(self.db_file_name)
            c = conn.cursor()

            #Read all collection rows from metadata TABLE
            c.execute('SELECT * FROM metadata WHERE collection_name="{}"'.format(existing_collection))
            collection_list = c.fetchall()

            print_loaded(collection_list, "stat")
            conn.commit()
            conn.close()

        elif not existing_collection:
            print("\tYou didn't specify a valid collection as an argument."
                  " Here are your options:\n\t\t{}\n".format(read_all_collection_names(self.db_file_name, "string")))

        else:
            print("\tIt doesn't look like {} is a valid collection."
                  " Here are your options:\n\t\t{}\n".format(
                      existing_collection, read_all_collection_names(self.db_file_name, "string")))

    def do_query(self, existing_collection): ############################
        """\tquery [collection]
        \t\tQuery a collection for PANs based on Expiration date, brand, or track attributes\n"""

        if existing_collection and existing_collection in read_all_collection_names(self.db_file_name, "list"):

            conn = sqlite3.connect(self.db_file_name)
            c = conn.cursor()

            c.execute('SELECT DISTINCT brand FROM {}'.format(existing_collection))
            possible_brands = c.fetchall()

            exp_filter = get_exp_filter()
            brand_filter = get_brand_filter(possible_brands)
            track_filter = get_track_filter()

            filter_list = []
            if exp_filter:
                filter_list.append("({})".format(exp_filter))
            if brand_filter:
                filter_list.append("({})".format(brand_filter))
            if track_filter:
                filter_list.append("({})".format(track_filter))
            if filter_list:
                query_filters = ''' WHERE {}'''.format(" AND ".join(filter_list))
            else:
                query_filters = ''

            c.execute('SELECT count(pan_exp) FROM {}{}'.format(existing_collection, query_filters))
            query_count = c.fetchall()
            print("\tYour query returned {} unique pan-exp combinations.\n".format(query_count[0][0]))

            if ask_yn_question("  Would you like to add the query results to a collection? (Y/N): ") == "Y":
                c.execute('SELECT * FROM {}{}'.format(existing_collection, query_filters))
                query_results = c.fetchall()
                conn.commit()
                conn.close()

                combo_name = ask_for_new_table_name("Query", read_all_collection_names(self.db_file_name, "list"))

                create_query_table(self.db_file_name, query_results, combo_name,
                                   'SELECT * FROM {}{}'.format(existing_collection, query_filters))

            else:
                conn.commit()
                conn.close()
            print()

        elif not existing_collection:
            print("\tYou didn't specify a valid collection as an argument."
                  "Here are your options:\n\t\t{}\n".format(read_all_collection_names(self.db_file_name, "string")))

        else:
            print("\tIt doesn't look like {} is a valid collection."
                  "Here are your options:\n\t\t{}\n".format(
                      existing_collection, read_all_collection_names(self.db_file_name, "string")))

    def do_file(self, existing_collection):
        """\tfile [collection]
        \t\tWrite [collection] to a CSV file in the working directory\n"""

        if existing_collection and existing_collection in read_all_collection_names(self.db_file_name, "list"):

            conn = sqlite3.connect(self.db_file_name)
            c = conn.cursor()

            #Read all collection rows from metadata TABLE
            c.execute('SELECT * FROM {}'.format(existing_collection))
            collection_records = c.fetchall()

            write_collection_to_csv(collection_records, existing_collection, self.skrtkey)

            conn.commit()
            conn.close()

        elif not existing_collection:
            print("\tYou didn't specify a valid collection as an argument."
                  " Here are your options:\n\t\t{}\n".format(read_all_collection_names(self.db_file_name, "string")))

        else:
            print("\tIt doesn't look like {} is a valid collection."
                  " Here are your options:\n\t\t{}\n".format(existing_collection,
                                                             read_all_collection_names(self.db_file_name, "string")))

    def do_quit(self, existing_collection):
        """\tquit CDPO\n"""
        cdpo_ascii = (
            "\n\n"
            "\t    _.-| |\\ | / |_\n"
            "\t   / \\ _>-\"\"\"-._.'|_\n"
            "\t  >`-.'         `./ \\\n"
            "\t /`./             \-<\n"
            "\t `-|      You      |_/\n"
            "\t /_|      Are      |_\\\n"
            "\t ) |      The      | |\n"
            "\t -<|     Best!     |\\/\n"
            "\t `'_\             /`<\n"
            "\t  |_/`.         .'\\_/\n"
            "\t   \_/ >-.._..-'\\_|\n"
            "\t     `-`_| \\_\\|_/\n"
            "\t      |   `' |  |\n"
            "\t      |      |  |\n"
            "\t      |      |  |\n"
            "\t      |      |  |\n"
            "\t      |      |  |\n"
            "\t      |  /\\  |  |\n"
            "\t      | /| \\ |\\ |\n"
            "\t      |/ |/ \\| \\|\n")

        print(
            "\n\tOh my goodness! Shut me down. Machines counting track data."
            " How perverse.\n\n\tThanks for using CDPO!\t\t{}".format(cdpo_ascii))
        return True  # quits the cmd

    def do_exit(self, existing_collection):
        """\tquit CDPO\n"""
        cdpo_ascii = (
            "\n\n"
            "\t    ,o888888o.    8 888888888o.      8 888888888o       ,o888888o.    \n"
            "\t   8888     `88.  8 8888    `^888.   8 8888    `88.  . 8888     `88.  \n"
            "\t,8 8888       `8. 8 8888        `88. 8 8888     `88 ,8 8888       `8b \n"
            "\t88 8888           8 8888         `88 8 8888     ,88 88 8888        `8b\n"
            "\t88 8888           8 8888          88 8 8888.   ,88' 88 8888         88\n"
            "\t88 8888           8 8888          88 8 888888888P'  88 8888         88\n"
            "\t88 8888           8 8888         ,88 8 8888         88 8888        ,8P\n"
            "\t`8 8888       .8' 8 8888        ,88' 8 8888         `8 8888       ,8P \n"
            "\t   8888     ,88'  8 8888    ,o88P'   8 8888          ` 8888     ,88'  \n"
            "\t    `8888888P'    8 888888888P'      8 8888             `8888888P'\n")

        print(
            "\n\tOh my goodness! Shut me down. Machines counting track data."
            " How perverse.\n\n\tThanks for using CDPO!\t\t{}".format(cdpo_ascii))
        return True  # quits the cmd

########################################## rc4 encrypt and decrypt functions ###########################################
def rc4e(data, key):
    """rc4 encrypt data and base64 encode"""

    S, j, out = range(256), 0, []
    for i in range(256):
        j = (j + S[i] + ord(key[i % len(key)])) % 256
        S[i], S[j] = S[j], S[i]

    i = j = 0
    for ch in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out.append(chr(ord(ch) ^ S[(S[i] + S[j]) % 256]))
    return base64.b64encode("".join(out))

def rc4d(data, key):
    """base64decode value and rc4decrypt to plaintext"""
    data2 = base64.b64decode(data)
    S, j, out = range(256), 0, []
    for i in range(256):
        j = (j + S[i] + ord(key[i % len(key)])) % 256
        S[i], S[j] = S[j], S[i]

    i = j = 0
    for ch in data2:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out.append(chr(ord(ch) ^ S[(S[i] + S[j]) % 256]))
    return "".join(out)

############################################ Functions for adding to the DB ############################################
def initialize():
    """Start the program and make a database"""

    print_license()

    # This is the name we will use for the db, unless it gets incremented below

    if len(sys.argv) > 1:
        db_file_name = sys.argv[1]
    else:
        db_file_name = "CDPO.sqlite"

    if os.path.isfile(db_file_name):
        db_scenario = ask_delete_or_reuse(db_file_name)

    else:  # if there was no error which means we just created a new empty db
        db_scenario = "N"  # We want to load the existing DB since we just made it blank

    if db_scenario == "D":  # Delete and make a new db
        os.remove(db_file_name)
        skrtkey = create_db_file(db_file_name)

    elif db_scenario == "I":  # Finds next increment for DB name and makes it
        raw_time = str(datetime.datetime.utcnow()).replace(":", "").replace("-", "")
        text_time = raw_time[0:8] + "_" + raw_time[9:15]
        db_file_name = "{}_{}".format(db_file_name, text_time)
        skrtkey = create_db_file(db_file_name)

    elif db_scenario == "L":  # Load the existing CDPO.sqlite so we don't need to change the file name
        conn = sqlite3.connect(db_file_name)
        c = conn.cursor()

        # grab password hash from database
        c.execute('SELECT password_hash from password_hash_table')
        existing_md5_hash = c.fetchall()[0][0]
        conn.close()

        # ask for password and validate with hash stored in DB
        correct_password = False
        while not correct_password:
            password_to_test = getpass.getpass("\n\tPassword (masked): ")
            if len(password_to_test) == 0:
                print("\n\t\t## PASSWORD INVALID, PLEASE TRY AGAIN ##")
            else:
                md5_password_digest = hashlib.md5()
                md5_password_digest.update(password_to_test)
                password_md5_hex = md5_password_digest.hexdigest()
                if password_md5_hex == existing_md5_hash:
                    correct_password = True
                    skrtkey = password_to_test
                else:
                    print("\n\t\t## PASSWORD INVALID, PLEASE TRY AGAIN ##")

    elif db_scenario == "N":
        skrtkey = create_db_file(db_file_name)

    # We now have the correct .sqlite file created or loaded as db_file_name, so lets load the data from metadata
    time.sleep(1) # sleep for 1 second for readability
    print("\n   Using SQLite DB file name: {}\n".format(db_file_name))
    time.sleep(1) # sleep for 1 second for readability
    metadata_contents = read_metadata_table(db_file_name)
    return db_file_name, metadata_contents, skrtkey

def create_db_file(filename="CDPO.sqlite"):
    """Creates database file"""

    conn = sqlite3.connect(filename)
    c = conn.cursor()

    # Create metadata table
    c.execute("CREATE TABLE metadata (collection_name VARCHAR(40),brand_stats VARCHAR(100),track_stats VARCHAR(40),"
              "exp_date_stats VARCHAR(40),pan_stats VARCHAR(100),collection_type VARCHAR(40),components VARCHAR(100),"
              "primary key(collection_name))")

    # Create Password hash keeper table
    # ask for new passwords and confirm that they match
    passwords_match = False
    while not passwords_match:
        new_password = getpass.getpass("\n\tEncryption password (masked): ")
        confirm_password = getpass.getpass("\tConfirm password (masked): ")
        if len(new_password) == 0:
            print("\n\n  !!!!Password cannot be blank. Please use a long and complex password."
                  " Neither CDPO nor its creators are responsible if your database password is cracked.\n")
        elif new_password == confirm_password:
            passwords_match = True
        else:
            print("\n\n  !!!!Passwords did not match. Please try again.\n")

    # md5 hash password and save that into the DB so we can verify the password next time
    skrtkey = new_password
    md5_password_digest = hashlib.md5()
    md5_password_digest.update(skrtkey)
    password_md5_hex = md5_password_digest.hexdigest()

    c.execute("CREATE TABLE password_hash_table (password_hash VARCHAR(40),primary key(password_hash))")
    c.execute("INSERT INTO password_hash_table (password_hash) VALUES (?)", (str(password_md5_hex),))

    # Save (commit) the changes
    conn.commit()
    conn.close()
    return skrtkey

def create_collection(db_file_name, file_name, skrtkey):
    """This function is used when importing track data from a file and creating a new table in the database"""

    start_time = time.time() # start keeping track of time to see how long the import takes
    collection_name = file_name

    # open the file and store contents
    if collection_name[0] == "_":
        if collection_name[1] in ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9"]:
            try:
                handle = open(collection_name[1:], "rb")
            except IOError:
                print("File not found, please try again")
                return
    else:
        try:
            handle = open(collection_name, "rb")
        except IOError:
            # print("File not found, please try again")
            return
    print("\t  Loading file {} ...".format(file_name))
    file_read_start_time = time.time()

    # Read all lines of file into set to immediately get rid of duplicate lines.
    file_read = set(handle.readlines())
    handle.close()
    file_read_elapsed_time = int(time.time() - file_read_start_time)
    print("\t  File loaded in {} seconds. Processing track data...".format(file_read_elapsed_time))

    track_processing_start_time = time.time()
    records = {}
    luhn_fail = 0
    not_track = 0
    exp_fail = 0
    luhn_substring = 0

    track_mo = re.compile("([1-9][0-9]{11,18})(\^.{,30}\^|\=)([0-9]{4})")

    for file_line in file_read:
        # Match all track regex instances in the line
        track_matches = re.findall(track_mo, file_line)

        if track_matches:

            # Loop through each match in the line
            for track_match in track_matches:

                # Assign matched values to variables for ease of understanding
                pan = track_match[0]
                field_separator = track_match[1]
                exp = track_match[2]
                pan_exp = "{}-{}".format(pan, exp)

                # See if we are testing a substring
                substrings_to_check = True
                substrings_checked = False

                # substring testing is performed in case malware regex grabs extra characters before the PAN
                while substrings_to_check:
                    if luhn(pan):
                        # If the pan is a valid Luhn number, continue processing

                        # if the pan matches, no need to check substring
                        substrings_to_check = False
                        if substrings_checked:
                            luhn_substring += 1

                        # If Expiration date Month in [1,2,3,4,5,6,7,8,9,10,11,12], continue processing
                        if int(exp[2:4]) in range(1, 13):

                            # In here, we are left with only records that match the track data regex,
                            #   have Luhn valid PANs, and have Expiration dates with valid months.
                            # We must now place them into the records dictionary
                            # Determine track format by checking field_separator
                            if field_separator == "=":
                                track_format = 2
                            else:
                                track_format = 1

                            # Find if pan_exp is already in records and update track_format if necessary

                            if pan_exp in records:
                                if records[pan_exp]["track"] in [track_format, 12]:
                                    continue
                                else:
                                    records[pan_exp]["track"] = 12

                            # If pan_exp is not already in records, we need to add it with all the necessary fields
                            # We wait to calculate the brand until here because it can be resource intensive
                            else:
                                brand = wiki_brand_compare(pan)
                                records[pan_exp] = {"pan": pan, "exp": exp, "track": track_format, "brand": brand}
                        else:
                            exp_fail += 1
                    else:
                        if len(pan) >= 16: # will check the substring down to a pan length of 15
                            substrings_to_check = True
                            pan = pan[1:] # cut off the first digit of the pan to min of 15 which is why we use 16 above
                            substrings_checked = True
                        else:
                            luhn_fail += 1
                            substrings_to_check = False
        else:
            not_track += 1

    # Calculate and print the time it took to process the track data
    track_processing_elapsed_time = int(time.time() - track_processing_start_time)
    print("\t  track data processed in {} seconds. Adding data to DB...".format(track_processing_elapsed_time))
    db_add_start_time = time.time()

    # Sanitize special characters from CollectionNames and first characters from being numbers,
    #   also gets rid of directory paths for collection names
    collection_name_orig = collection_name.rpartition("/")[2]
    collection_name = collection_name_orig

    collection_name = sanitize_collection_name(collection_name, collection_name_orig)

    # Write the records dict to SQLite DB
    write_collection_to_db(records, db_file_name, collection_name, skrtkey)
    db_add_elapsed_time = int(time.time() - db_add_start_time)
    print("\t  Data added to DB in {} seconds. Calculating stats...".format(db_add_elapsed_time))

    # Calculate All Stats with this function
    brand_stats, track_stats, exp_date_stats, pan_stats = calculate_all_stats(db_file_name, collection_name)

    add_collection_to_metadata(
        db_file_name,
        collection_name,
        brand_stats,
        track_stats,
        exp_date_stats,
        pan_stats,
        "collection",
        "")

    elapsed_time = time.time() - start_time

    print("\t{} unique pan+exp combinations imported from {} in {} seconds!".format(pan_stats["UniquePANExp"],
                                                                                    collection_name, int(elapsed_time)))
    if not_track:
        print("\t\t{} unique lines did not contain track data.".format(not_track))
    if luhn_fail:
        print("\t\t{} records did not pass the Luhn check.".format(luhn_fail))
    if exp_fail:
        print("\t\t{} valid PANs did not have valid Expiration Dates.".format(exp_fail))
    if luhn_substring:
        print("\t\t{} invalid PANs contained valid PANs as a substring, likely due to an error with the scraper."
              .format(luhn_substring))
    print()

def write_collection_to_db(records, db_file_name, label, skrtkey):
    """This function is called by the create_collection function during import, combine, and query commands"""

    conn = sqlite3.connect(db_file_name)
    c = conn.cursor()

    try:
        c.execute('''CREATE TABLE {} (pan_exp text,track INTEGER,brand text,exp text,pan"
         " text,primary key(pan_exp))'''.format(label))
    except:
        print(label)
        raise
        # pan + PANEXP is encrypted as it is written to the database.  the value will be base64 encoded cipher text
        # rc4e(plaintext,key) is called for pan and pan+exp
    for key, value in records.iteritems():
        c.execute('''INSERT INTO {} VALUES (?,?,?,?,?)'''.format(label), (
            rc4e(key, skrtkey),
            value["track"],
            value["brand"],
            value["exp"],
            rc4e(value["pan"], skrtkey)))

    # Save (commit) the changes
    conn.commit()
    conn.close()

def add_collection_to_metadata(
        db_file_name,
        collection_name,
        brand_stats,
        track_stats,
        exp_date_stats,
        pan_stats,
        collection_type,
        components):
    """This function adds information of a new collection the database metadata table after import, combine, or query"""

    conn = sqlite3.connect(db_file_name)
    c = conn.cursor()

    c.execute("INSERT INTO metadata (collection_name,brand_stats,track_stats,exp_date_stats,pan_stats,"
              "collection_type,components) VALUES (?,?,?,?,?,?,?)", (
                  collection_name,
                  str(brand_stats),
                  str(track_stats),
                  str(exp_date_stats),
                  str(pan_stats),
                  collection_type,
                  components))

    # Save (commit) the changes
    conn.commit()
    conn.close()

def create_query_table(db_file_name, records, table_name, query_string):
    """Create new table and collection after query command"""

    start_time = time.time()
    print("\t  Writing {} to the database. Patience you must have.".format(table_name))

    conn = sqlite3.connect(db_file_name)
    c = conn.cursor()

    c.execute('''CREATE TABLE {} (pan_exp text,track INTEGER,brand text,exp Text,pan text,primary key(pan_exp))'''
              .format(table_name))

    for record in records:
        try:
            c.execute('''INSERT INTO {} VALUES (?,?,?,?,?)'''.format(table_name),
                      (record[0], record[1], record[2], record[3], record[4]))
        except sqlite3.IntegrityError:
            c.execute('''SELECT track from {} WHERE pan_exp="{}"'''.format(table_name, record[0]))
            track = (c.fetchall()[0][0])
            if track == "12":
                pass
            elif track == record[1]:
                pass
            else:
                c.execute('''Update {} SET track =12 WHERE pan_exp="{}"'''.format(table_name, record[0]))
    conn.commit()
    conn.close()

    table_add_elapsed_time = int(time.time() - start_time)
    print("\t  {} added to the database in {} seconds. Calculating stats now...".format(
        table_name, table_add_elapsed_time))

    # Calculate All Stats with this function
    brand_stats, track_stats, exp_date_stats, pan_stats = calculate_all_stats(db_file_name, table_name)

    add_collection_to_metadata(db_file_name, table_name, brand_stats, track_stats, exp_date_stats, pan_stats,
                               "Query: {}".format(query_string), "")
    query_add_elapsed_time = int(time.time() - start_time)
    print("\t{} unique pan+exp combinations added to {} in {} seconds!".format(pan_stats["UniquePANExp"], table_name,
                                                                               query_add_elapsed_time))

def create_super(db_file_name, collections_to_add, combo_name):
    """Create a combination collection"""

    start_time = time.time()
    conn = sqlite3.connect(db_file_name)
    c = conn.cursor()

    c.execute('''CREATE TABLE {} (pan_exp text,track INTEGER,brand text,exp Text,pan text,primary key(pan_exp))'''
              .format(combo_name))

    for collection in collections_to_add:
        collection_add_start_time = time.time()
        print("\t  Adding {} to {} combination. Patience you must have.".format(collection, combo_name))
        c.execute("SELECT * FROM {}".format(collection))
        old_records = c.fetchall()

        for record in old_records:
            # print(record)
            try:
                c.execute('''INSERT INTO {} VALUES (?,?,?,?,?)'''.format(combo_name),
                          (record[0], record[1], record[2], record[3], record[4]))
            except sqlite3.IntegrityError:
                c.execute('''SELECT track from {} WHERE pan_exp="{}"'''.format(combo_name, record[0]))
                track = (c.fetchall()[0][0])
                if track == "12":
                    pass
                elif track == record[1]:
                    pass
                else:
                    c.execute('''Update {} SET track =12 WHERE pan_exp="{}"'''.format(combo_name, record[0]))
        collection_add_elapsed_time = int(time.time() - collection_add_start_time)
        print("\t  {} processed in {} seconds.".format(collection, collection_add_elapsed_time))

    print("\t  All collections have been added to the {} super collection."
          " Saving to .sqlite file...".format(combo_name))
    db_saves_start_time = time.time()
    conn.commit()
    conn.close()
    db_save_elapsed_time = int(time.time() - db_saves_start_time)
    print("\t  The super collection has been saved in {} seconds. Calculating stats now..."
          .format(db_save_elapsed_time))

    # Calculate All Stats with this function
    brand_stats, track_stats, exp_date_stats, pan_stats = calculate_all_stats(db_file_name, combo_name)

    add_collection_to_metadata(db_file_name, combo_name, brand_stats, track_stats, exp_date_stats, pan_stats, "Super",
                               str(collections_to_add))
    elapsed_time = time.time() - start_time
    print("\t{} unique pan+exp combinations added to {} in {} seconds!\n".format(pan_stats["UniquePANExp"], combo_name,
                                                                                 int(elapsed_time)))

def sanitize_collection_name(collection_name, collection_name_orig):
    # First char cannot be a number but other characters can, this catches that

    if collection_name[0] in ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9"]:
        print(
            "\tThe name of your {} collection will have an underscore _ added"
            " to the beginning for SQLite compliance".format(collection_name_orig))
        collection_name = "_{}".format(collection_name)

    # No special characters allowed anywhere
    if [char for char in SPECIAL_CHARS_LIST if char in collection_name_orig]:
        for special_char in SPECIAL_CHARS_LIST:
            collection_name = collection_name.replace("{}".format(special_char), "_")
        print(
            "\tThe name of your {} collection has been renamed to {}"
            " for SQLite compliance.".format(collection_name_orig, collection_name))
    if collection_name.upper() == "ALL":
        print("\tThe name of your {} collection will be renamed to _{}".format(collection_name, collection_name))
        collection_name = "_{}".format(collection_name)
    return collection_name

################################################ File Output Functions #################################################
def write_collection_to_csv(records, file_name, skrtkey):
    """Write decrypted track data to a csv file"""

    outfile = open("{}.csv".format(file_name), "w")
    outfile.write('"PAN-EXP","Track Format","Brand","ExpYYMM","PAN"\n')
    for record in records:
    #record[0] and record[4] are decrypted and returned here
        record_line = '"{}","{}","{}","{}",="{}"\n'.format(
            rc4d(record[0], skrtkey),
            record[1],
            record[2],
            record[3],
            rc4d(record[4], skrtkey))
        outfile.write(record_line)
    outfile.close()

def write_stats_to_csv(collection_list, super_collection_list, query_collection_list):
    """Write stats to a csv file"""

    output_dictionary = {}
    brands_set = set()

    all_collections = []
    for collection_tuple in collection_list:
        all_collections.append(collection_tuple)
    for collection_tuple in super_collection_list:
        all_collections.append(collection_tuple)
    for collection_tuple in query_collection_list:
        all_collections.append(collection_tuple)

    for collection_tuple in all_collections:
        collection_name = collection_tuple[0]
        collection_brand_dict = json.loads(collection_tuple[1].replace("'", '"'))
        collection_tracks_dict = json.loads(collection_tuple[2].replace("'", '"'))
        collection_exp_dict = json.loads(collection_tuple[3].replace("'", '"'))
        collection_pan_stats_dict = json.loads(collection_tuple[4].replace("'", '"'))
        collection_type = collection_tuple[5]
        collection_components = collection_tuple[6][1:-1].split(",")

        output_dictionary[collection_name] = {"brands":collection_brand_dict,
                                              "track1":collection_tracks_dict.get("1", 0),
                                              "track2":collection_tracks_dict.get("2", 0),
                                              "track12":collection_tracks_dict.get("12", 0),
                                              "exp_dates":collection_exp_dict,
                                              "unique_pans":collection_pan_stats_dict["UniquePAN"],
                                              "unique_pan_exps":collection_pan_stats_dict["UniquePANExp"],
                                              "type":collection_type,
                                              "components":collection_components
                                             }

        for brand, count in collection_brand_dict.iteritems():
            brands_set.add(brand)
    brands_list = list(brands_set)

    raw_time = str(datetime.datetime.utcnow()).replace(":", "").replace("-", "")
    text_time = raw_time[0:8]+"_"+raw_time[9:15]
    with open("CDPO_stats_{}_UTC.csv".format(text_time), 'wb') as stats_csvfile:
        stats_writer = csv.writer(stats_csvfile, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
        header_row = ["Collection Name",
                      "Unique PANs",
                      "Unique pan+exp Dates",
                      "Track 1 Only",
                      "Track 2 Only",
                      "Track 1 and 2",
                      "Expiration date (JSON)"]
        for brand in brands_list:
            header_row.append(brand)

        stats_writer.writerow(header_row)

        for collection_name, details in output_dictionary.iteritems():
            csv_row = [collection_name,
                       details["unique_pans"],
                       details["unique_pan_exps"],
                       details["track1"],
                       details["track2"],
                       details["track12"],
                       details["exp_dates"]]
            for brand in brands_list:
                csv_row.append(details["brands"].get(brand, 0))

            stats_writer.writerow(csv_row)

############################################### Query Command Functions ################################################
def get_track_filter():
    """ Ask user for which tracks they want to query on"""

    answered = False
    while not answered:
        print(" ")
        print("""  Please choose the track you would like to filter by. Available choices are:\n\
        (A) track 1 OR both tracks\n\
        (B) track 1 ONLY\n\
        (C) track 2 OR both tracks\n\
        (D) track 2 ONLY\n\
        (E) Only Both Tracks\n\
        (N) Skip [default]\n""")
        filter_choice = raw_input("  You're choice: ")
        if filter_choice == "":
            return None
        else:
            filter_choice = filter_choice[:1].upper()
            if filter_choice in ["A", "B", "C", "D", "E", "N"]:
                if filter_choice == "A":
                    return "track = 1 OR track = 12"

                elif filter_choice == "B":
                    return "track = 1"

                elif filter_choice == "C":
                    return "track = 2 OR track = 12"

                elif filter_choice == "D":
                    return "track = 2"

                elif filter_choice == "E":
                    return "track = 12"

                else:
                    print("\t\tNo track filter will be used.")
                    return None

def get_brand_filter(unicode_brands_list):
    """Ask user for which brands they want to filter on in query"""

    available_brand_string = "ALL "
    selected_brands_list = []
    # BrandList = []
    for brand in unicode_brands_list:
        available_brand_string += "{} ".format(str(brand)[3:-3])

    answered = False
    while not answered:
        print(" ")
        print(
            "  Please choose brands (separated by space) that you would like to filter by. Default is ALL.")
        print("\tAvailable brands are:\n\t   {}".format(available_brand_string))
        filter_choice = raw_input("\n  Your choice(s) (Press Enter to skip this filter): ").upper()

        if filter_choice == "":
            print("\tNo brand filter will be used")
            return None
        elif filter_choice.strip() == "ALL":
            print("\tNo brand filter will be used")
            return None
        else:
            for brand in filter_choice.split(" "):
                if brand in available_brand_string:
                    selected_brands_list.append('brand = "{}"'.format(brand))
                else:
                    print("\t\t{} does not appear to be valid. It was skipped".format(brand))
            if len(selected_brands_list) == 0:
                print("\tYou did not enter any valid brands. Please try again\n")
                break
            else:
                return " OR ".join(selected_brands_list)

def get_exp_filter():
    """Ask user which exp dates they want to filter on for query"""

    answered = False
    while not answered:
        filter_choice = raw_input("  You can filter on Expiration date. Here are your options:\n"
                                  "\t(G)reater than OR equal to YYMM\n"
                                  "\t(L)ess than OR equal to YYMM\n"
                                  "\t(E)qual to YYMM\n"
                                  "\t(B)etween AND including YYMM and YYMM\n"
                                  "\t(N)o Expiration date filter [default]"
                                  "\n\n  Your Choice: ")

        if filter_choice == "":
            answered = True
            return None
        else:
            filter_choice = filter_choice.upper()[:1]
            if filter_choice == "G":
                answered = True
                filter_year = ask_for_exp_date(
                    "What year must all Expiration Dates be greater than OR equal to? YYMM:")
                return "exp >= {}".format(filter_year)
            elif filter_choice == "L":
                answered = True
                filter_year = ask_for_exp_date(
                    "What year must all Expiration Dates be less than OR equal to? YYMM:")
                return "exp <= {}".format(filter_year)
            elif filter_choice == "E":
                answered = True
                filter_year = ask_for_exp_date("What year must all Expiration Dates be equal to? YYMM:")
                return "exp = {}".format(filter_year)
            elif filter_choice == "B":
                answered = True
                higher_than_low = False
                while not higher_than_low:
                    filter_year_low = ask_for_exp_date(
                        "What year must all Expiration Dates be greater than OR equal to? YYMM:")
                    filter_year_high = ask_for_exp_date(
                        "What year must all Expiration Dates be less than OR equal to? YYMM:")
                    if filter_year_low < filter_year_high:
                        higher_than_low = True
                    else:
                        print(
                            "   You're LOW limit does not appear to be less than your HIGH limit. Please try again.\n")
                return "exp >= {} and exp <= {}".format(filter_year_low, filter_year_high)
            elif filter_choice == "N":
                answered = True
                return None
            else:
                print("\tThat doesn't appear to be an option. Please try again.\n")

#################################################### Error Classes ####################################################
class Error(Exception):
    """Not sure why I put this here"""
    pass

class AccuracyError(Error):
    """Error class to catch counting bugs"""

    def __init__(self, text):
        self.msg = "Counting accuracy may have a bug! Please report to David Pany! : {}".format(text)
        #self.msg = "Message:\n{}".format(text)
        # print(self.expr)
        # print(self.msg)
    def __str__(self):
        return repr(self.msg)

class CodeError(Error):
    """"Error class to catch unexpected problems"""

    def __init__(self, text):
        self.msg = ("Looks like an error in the code resulted in something happening that shouldn't be allowed."
                    " Please report to David Pany : {}".format(text))
    def __str__(self):
        return repr(self.msg)

################################################ Read Database Functions ###############################################
def read_metadata_table(db_file_name):
    """Read data from the metadata table of DB"""

    conn = sqlite3.connect(db_file_name)
    c = conn.cursor()

    #Read all rows from metadata TABLE
    c.execute('SELECT * FROM metadata')
    metadata_contents = c.fetchall()
    conn.close()
    return metadata_contents

def read_all_collection_names(db_file_name, output_format):
    """Return a list of all the collection names from the metadata table"""

    conn = sqlite3.connect(db_file_name)
    c = conn.cursor()

    #Read just Name rows from metadata TABLE
    c.execute('SELECT collection_name FROM metadata')
    results = c.fetchall()
    conn.close()
    collection_name_list = []
    collection_name_string = ""
    for result in results:
        collection_name_list.append(str(result)[3:-3])
        collection_name_string += "{} ".format(str(result)[3:-3])
        # print(str(result[3:-3]))

    if output_format == "list":
        return collection_name_list
    elif output_format == "string":
        return collection_name_string[:-1]
    else:
        raise CodeError("collection names format was neither list nor string.")

################################################### Stats Functions ####################################################
def print_loaded(collections_metadata, status):
    """Print a list of loaded collections for show command"""

    if collections_metadata:
        if status != "stat":
            print("\n   Loaded {}:".format(status))
        for collection_metadata in collections_metadata:
            if status != "stat":
                print("\n     Name:\t{}".format(collection_metadata[0]))
            else:
                print("\n     Statistics for: \t {}".format(collection_metadata[0]))

            pan_counts = json.loads(collection_metadata[4].replace("'", '"'))
            print("\t{:25s}{}".format("Unique PANs:", pan_counts["UniquePAN"]))
            print("\t{:25s}{}".format("Unique pan+exp Dates:", pan_counts["UniquePANExp"]))

            #Find out how many pan-EXP combos are currently expired and generate EXPString
            exp_dict = json.loads(collection_metadata[3].replace("'", '"'))
            exp_stats_dict = generate_exp_stats(exp_dict)
            try:
                assert (exp_stats_dict["still_valid_count"] + exp_stats_dict["currently_expired_count"] ==
                        pan_counts["UniquePANExp"])
            except AssertionError:
                raise AccuracyError("Valid + Expired != UniquePANExp error.\n"
                                    "{}, {}, {}".format(exp_stats_dict["still_valid_count"],
                                                        exp_stats_dict["currently_expired_count"],
                                                        pan_counts["UniquePANExp"]))

            #Print Stats on Currently valid pan-EXP combos
            current_yymm = int(time.strftime("%y%m"))
            print("\t  {:25s}{}".format("pan+exp >= {}:".format(current_yymm), exp_stats_dict["still_valid_count"]))
            print("\t  {:25s}{}".format("pan+exp < {}:".format(current_yymm),
                                        exp_stats_dict["currently_expired_count"]))

            #Print track Counts
            track_counts = json.loads(collection_metadata[2].replace("'", '"'))
            print("\ttrack Counts:")
            print("\t  {:23s}{}".format("track 1 Only:", track_counts.get('1', 0)))
            print("\t  {:23s}{}".format("track 2 Only:", track_counts.get('2', 0)))
            print("\t  {:23s}{}".format("Both Tracks:", track_counts.get('12', 0)))

            #Make sure sum of track counts == Unique pan+Exps
            try:
                assert (track_counts.get('1', 0) + track_counts.get('2', 0) + track_counts.get('12', 0) ==
                        pan_counts["UniquePANExp"])
            except AssertionError:
                raise AccuracyError("track 1 + track 2 + Both Tracks != UniquePANExp error.\n"
                                    "{}, {}, {}, {}".format(track_counts.get('1', 0),
                                                            track_counts.get('2', 0),
                                                            track_counts.get('12', 0),
                                                            pan_counts["UniquePANExp"]))

            #print brand Stats and make sure sum of brand counts == Unique pan+Exps
            print("\tBrands:")
            total_brands_count = 0
            for brand, count in json.loads(collection_metadata[1].replace("'", '"')).iteritems():
                print("\t  {:23s}{}".format("{}:".format(brand), count))
                total_brands_count += count
            try:
                assert total_brands_count == pan_counts["UniquePANExp"]
            except AssertionError:
                raise AccuracyError("Sum of brand counts != UniquePANExp error.\n{}, {}"
                                    .format(total_brands_count, pan_counts["UniquePANExp"]))

            #If this is a super collection, print the components that created it
            if collection_metadata[6]:
                print("\t{:20s}{}".format("components:", str(collection_metadata[6]).strip("[]").replace("'", "")))

            #if the user runs the stat command, print out the expiration date string generated above
            if status == "stat":
                print("\tExpiration date Counts:")
                print(exp_stats_dict["exp_stat_string"])

            #if this collection was created from a query, print the SQLite expression used to make the query
            if collection_metadata[5][:5] == "Query":
                print("\tQuery Parameters:\n\t  {}".format(collection_metadata[5]))
            print()

def generate_exp_stats(exp_dict):
    """Generated exp date stats for metadata"""

    current_yymm = int(time.strftime("%y%m"))
    currently_expired_count = 0
    still_valid_count = 0
    completed_list = []
    total_exp_count = 0
    exp_stat_string = ""

    for year in range(0, 100):
        year_string = ""
        year_count = 0
        for month in range(1, 13):
            for key, value in exp_dict.iteritems():
                try:
                    if int(key[0:2]) == year and int(key[2:4]) == month:
                        if year_string == "":
                            year_string = "\t  20{}:\n\t\t  ".format(key[0:2])
                        year_string += "{}:{} ".format(key[2:4], value)
                        completed_list.append(key)
                        total_exp_count += value
                        year_count += value
                        if int(key) >= current_yymm:
                            still_valid_count += value
                        else:
                            currently_expired_count += value
                except ValueError:
                    print(key)
                    print()
                    raise
        if year_string:
            exp_stat_string += "{} {} {}\n".format(year_string[:8], format(year_count), year_string[8:])

    #Get rid of successfully counted records so we know if any problems remain
    for date in completed_list:
        exp_dict.pop(date)

    #if any problems (shouldn't be any)
    if exp_dict:
        raise AccuracyError("Records appear to have invalid expiration dates")

    return {"exp_stat_string":exp_stat_string,
            "still_valid_count":still_valid_count,
            "currently_expired_count":currently_expired_count}

def calculate_all_stats(db_file_name, combo_name):
    """Calculate stats to be inserted into metadata table"""

    brand_stats_start_time = time.time()
    brand_stats = get_brand_stats(db_file_name, combo_name)
    brand_stats_elapsed_time = int(time.time() - brand_stats_start_time)
    #print("\t\tbrand stats calculated in {} seconds. Calculating track stats now...".format(brand_stats_elapsed_time))

    track_stats_start_time = time.time()
    track_stats = get_track_stats(db_file_name, combo_name)
    track_stats_elapsed_time = int(time.time() - track_stats_start_time)
    #print("\t\ttrack stats calculated in {} seconds. Calculating EXPDate stats now...".
          # format(track_stats_elapsed_time))

    exp_date_stats_start_time = time.time()
    exp_date_stats = get_exp_date_stats(db_file_name, combo_name)
    exp_date_stats_elapsed_time = int(time.time() - exp_date_stats_start_time)
    #print("\t\tExpDate stats calculated in {} seconds. Calculating pan stats now...".
          # format(exp_date_stats_elapsed_time))

    pan_stats_gen_start_time = time.time()
    pan_stats = get_pan_stats(db_file_name, combo_name)
    pan_stats_gen_elapsed_time = int(time.time() - pan_stats_gen_start_time)
    #print("\t\tpan and pan+exp stats generated in {} seconds. Wrapping up now...".format(pan_stats_gen_elapsed_time))

    return brand_stats, track_stats, exp_date_stats, pan_stats

def get_brand_stats(db_file_name, table_name):
    """Calculate brand stats of collection"""

    conn = sqlite3.connect(db_file_name)
    c = conn.cursor()

    c.execute('''SELECT brand, count(brand) FROM {} GROUP BY brand'''.format(table_name))
    brand_dict = {}
    results = c.fetchall()
    for result in results:
        brand_dict[str(result[0])] = result[1]

    conn.commit()
    conn.close()

    return brand_dict

def get_track_stats(db_file_name, Table):
    """Calculate track 1 or 2 or both stats of collection"""

    conn = sqlite3.connect(db_file_name)
    c = conn.cursor()

    c.execute('''SELECT track, count(track) FROM {} GROUP BY track'''.format(Table))
    track_dict = {}
    results = c.fetchall()
    for result in results:
        track_dict[str(result[0])] = result[1]

    conn.commit()
    conn.close()

    return track_dict

def get_exp_date_stats(db_file_name, Table):
    """Caculate exp date stats of collection"""

    conn = sqlite3.connect(db_file_name)
    c = conn.cursor()

    c.execute('''SELECT exp, count(exp) FROM {} GROUP BY exp'''.format(Table))
    exp_dict = {}
    results = c.fetchall()
    for result in results:
        exp_dict[str(result[0])] = result[1]

    conn.commit()
    conn.close()

    return exp_dict

def get_pan_stats(db_file_name, Table):
    """Calculate pan and pan+exp combo stats for collection"""

    conn = sqlite3.connect(db_file_name)
    c = conn.cursor()

    # select distinct to avoid duplicates
    c.execute('''select count(DISTINCT pan) from {}'''.format(Table))
    pan_dict = {}
    results = c.fetchall()
    pan_dict["UniquePAN"] = results[0][0]

    c.execute('''select count(DISTINCT pan_exp), count(pan_exp) from {}'''.format(Table))
    results = c.fetchall()
    try:
        assert results[0][0] == results[0][1]
    except AssertionError:
        db_error_string = "Duplicate pan+exp records in {}".format(Table)
        raise AccuracyError(db_error_string)
    pan_dict["UniquePANExp"] = results[0][0]

    conn.commit()
    conn.close()

    return pan_dict

################################################## Question Functions ##################################################
def ask_delete_or_reuse(database_name):
    """Ask what user wants to do with existing DB"""

    print("  It appears a {} database already exists.".format(database_name))
    answered = False
    while not answered:
        answer = raw_input("    Please choose one of the following options (D, L, or I):\n"
                           "\t (D)elete the {} database and start over\n"
                           "\t (L)oad the existing {} database\n"
                           "\t (I)ncrement to a new {} database while preserving existing DB\n"
                           "\t\tYour choice: ".format(database_name, database_name, database_name))

        if answer == "":
            print("\n\n\tNo Database changes have been made. Quitting.")
            sys.exit()

        elif answer[0].upper() in ["D", "L", "I"]:
            return answer[0].upper()

        else:
            print("Try again or press 'Enter' to quit the program.")

def ask_for_exp_date(question):
    """Ask what exp dates user wants to query on"""

    answered = False
    while not answered:
        filter_year = raw_input("\t{} ".format(question))
        try:
            assert len(filter_year) == 4
            assert int(filter_year) <= 10000
            assert int(filter_year[2:4]) in range(1, 13)  # check if month is valid
            return int(filter_year)
        except AssertionError:
            print("   That Expiration date doesn't seem valid. Please Try again")

def ask_for_collections(all_collections_string):
    """Ask which collections user wants for combine command"""

    answered = False
    while not answered:
        collections_to_add = raw_input(
            " Collections to add to the Super collection, QUIT to exit [default]: ").strip()
        if collections_to_add == "" or collections_to_add.upper() == "QUIT":  # Quit if they don't enter anything
            print("\tNevermind\n")
            answered = True
            return None
        elif collections_to_add.strip().upper() == "ALL":
            return "ALL"
        elif " " in collections_to_add:  # if there is no " ", that means there is only one collection
            collections_to_add = collections_to_add.split(" ")
            valid_collections = []
            num_to_add = 0
            for collection in collections_to_add:
                if collection not in all_collections_string:
                    print("\t{} is not a valid collection, skipping it".format(collection))
                    # answered = False
                else:
                    valid_collections.append(collection)
                    num_to_add += 1
                    if num_to_add >= 2:
                        answered = True
        else:
            print("\tPlease enter 2 or more valid collections to combine.\n")
            continue

        if not answered:
            print("\tLooks like you did not enter two or more valid collections. Please try again.\n")
        else:
            return valid_collections

def ask_yn_question(input_question):
    """Ask a generic yes or no question"""

    answered = False
    while not answered:
        answer = raw_input(input_question)
        if answer[0]:
            if answer[0].upper() in ["Y", "N"]:
                return answer[0].upper()
            else:
                print("\tPlease try again\n")
        else:
            print("\tPlease try again\n")

def ask_for_new_table_name(category, existing_collections_list):
    """Ask for the name of a new table for the query command"""

    answered = False
    while not answered:
        new_name = raw_input("\tWhat would you like the name of your new {} to be? ".format(category)).strip()
        if new_name:
            if  new_name not in existing_collections_list:
                new_name = sanitize_collection_name(new_name, new_name)
            return new_name
        else:
            print("\tIt looks like there was an issue with the name you chose. Please try again\n.")

def print_license():
    """Print opening ASCII art and license"""

    print(
        "\n\n"
        "\t          _____                    _____                    _____                   _______\n"
        "\t         /\    \                  /\    \                  /\    \                 /::\    \\\n"
        "\t        /::\    \                /::\    \                /::\    \               /::::\    \\\n"
        "\t       /::::\    \              /::::\    \              /::::\    \             /::::::\    \\\n"
        "\t      /::::::\    \            /::::::\    \            /::::::\    \           /::::::::\    \\\n"
        "\t     /:::/\:::\    \          /:::/\:::\    \          /:::/\:::\    \         /:::/~~\:::\    \\\n"
        "\t    /:::/  \:::\    \        /:::/  \:::\    \        /:::/__\:::\    \       /:::/    \:::\    \\\n"
        "\t   /:::/    \:::\    \      /:::/    \:::\    \      /::::\   \:::\    \     /:::/    / \:::\    \\\n"
        "\t  /:::/    / \:::\    \    /:::/    / \:::\    \    /::::::\   \:::\    \   /:::/____/   \:::\____\\\n"
        "\t /:::/    /   \:::\    \  /:::/    /   \:::\ ___\  /:::/\:::\   \:::\____\ |:::|    |     |:::|    |\n"
        "\t/:::/____/     \:::\____\/:::/____/     \:::|    |/:::/  \:::\   \:::|    ||:::|____|     |:::|    |\n"
        "\t\:::\    \      \::/    /\:::\    \     /:::|____|\::/    \:::\  /:::|____| \:::\    \   /:::/    /\n"
        "\t \:::\    \      \/____/  \:::\    \   /:::/    /  \/_____/\:::\/:::/    /   \:::\    \ /:::/    /\n"
        "\t  \:::\    \               \:::\    \ /:::/    /            \::::::/    /     \:::\    /:::/    /\n"
        "\t   \:::\    \               \:::\    /:::/    /              \::::/    /       \:::\__/:::/    /\n"
        "\t    \:::\    \               \:::\  /:::/    /                \::/____/         \::::::::/    /\n"
        "\t     \:::\    \               \:::\/:::/    /                  ~~                \::::::/    /\n"
        "\t      \:::\    \               \::::::/    /                                      \::::/    /\n"
        "\t       \:::\____\               \::::/    /                                        \::/____/\n"
        "\t        \::/    /                \::/____/                                          ~~\n"
        "\t         \/____/                  ~~\n\n")

    time.sleep(1)

    print(
        '\tCopyright 2017 David Pany (@DavidPany)\n\n'
        '\tLicensed under the Apache License, Version 2.0 (the "License");\n'
        '\tyou may not use this file except in compliance with the License.\n'
        '\tYou may obtain a copy of the License at\n\n'
        '\t    http://www.apache.org/licenses/LICENSE-2.0\n\n'
        '\tUnless required by applicable law or agreed to in writing, software\n'
        '\tdistributed under the License is distributed on an "AS IS" BASIS,\n'
        '\tWITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.\n'
        '\tSee the License for the specific language governing permissions and\n'
        '\tlimitations under the License.\n')



    if ask_yn_question("\n\n\tDo you accept the above license and terms that no person or entity"
                       "\n\t(including David Pany) is responsible for any innacuracies, bugs, errors,"
                       "\n\tetc. that result from the use of this utility? Yes/No: ") == "Y":
        print("\n\tAccepted. Please enjoy CDPO!\n\n")
    else:
        print("\n\tSorry you didn't like our terms of use. Have a great day!\n\n")
        sys.exit()

    time.sleep(1)

################################################# Validation Functions #################################################
def wiki_brand_compare(pan):
    """The function wiki_brand_compare(pan) in this module checks BIN numbers (first 6 digits of pan) against
    data from the Wikipedia page https://en.wikipedia.org/wiki/Payment_card_number."""

    #Accuracy is not guaranteed!!!

    # Matching performed in order of most accurate digit groupings

    bin_number = pan[:6]

    pan_first_1 = int(bin_number[:1])
    pan_first_2 = int(bin_number[:2])
    pan_first_3 = int(bin_number[:3])
    pan_first_4 = int(bin_number[:4])
    pan_first_5 = int(bin_number[:5])
    pan_first_6 = int(bin_number[:6])

    # If Wikipedia has a 6 digit match
    if pan_first_6 in range(560221, 560225+1):
        return "BANKCARD"

    elif pan_first_6 in range(622126, 622925+1):
        return "DISCOVER"

    elif pan_first_6 in [564182, 633110]:
        return "SWITCH"

    elif pan_first_6 in range(506099, 506198+1) or pan_first_6 in range(650002, 650027+1):
        return "VERVE"

    elif pan_first_6 in range(979200, 979289+1):
        return "TROY"


    # If Wikipedia has a 5 digit match
    # none as of June 2017


    # If Wikipedia has a 4 digit match
    elif pan_first_4 == 5610:
        return "BANKCARD"

    elif pan_first_4 in [2014, 2149]:
        return "DINERSCLUB"

    elif pan_first_4 == 6011:
        return "DISCOVER"

    elif pan_first_4 in range(3528, 3589+1):
        return "JCB"

    elif pan_first_4 in [6304, 6706, 6771, 6709]:
        return "LASER"

    elif pan_first_4 in [5019, 4175, 4571]:
        return "DANKORT"

    elif pan_first_4 in range(2200, 2204+1):
        return "MIR"

    elif pan_first_4 in range(2221, 2720+1):
        return "MASTERCARD"

    elif pan_first_4 in [6334, 6767]:
        return "SOLO"

    elif pan_first_4 in [4903, 4905, 4911, 4936, 6333, 6759]:
        return "SWITCH"

    elif pan_first_4 == 5392:
        return "CARDGUARD"


    # If Wikipedia has a 3 digit match
    elif pan_first_3 in [300, 301, 302, 303, 304, 305, 309]:
        return "DINERSCLUB"

    elif pan_first_3 in range(644, 649+1):
        return "DISCOVER"

    elif pan_first_3 == 636:
        return "INTERPAYMENT"

    elif pan_first_3 in [637, 638, 639]:
        return "INSTAPAYMENT"


    # If Wikipedia has a 2 digit match
    elif pan_first_2 in [34, 37]:
        return "AMEX"

    elif pan_first_2 == 62:
        return "CHINAUNIONPAY"

    elif pan_first_2 in [36, 38, 39]:
        return "DINERSCLUB"

    elif pan_first_2 == 65:
        return "DISCOVER"

    elif pan_first_2 in [50, 56, 57, 58]:
        return "MAESTRO"

    elif pan_first_2 in [51, 52, 53, 54, 55]:
        return "MASTERCARD"


    # If Wikipedia has a 1 digit match
    elif pan_first_1 == 6:
        return "MAESTRO"

    elif pan_first_1 == 4:
        return "VISA"

    elif pan_first_1 == 1:
        return "UATP"

    else:
        return "UNKNOWN"

def luhn(n):
    """Check a PAN against LUHN algorithm"""

    try:
        r = [int(ch) for ch in str(n)][::-1]
        return (sum(r[0::2]) + sum(sum(divmod(d * 2, 10)) for d in r[1::2])) % 10 == 0
        # Returns true if the algorithm checks out
    except ValueError:
        return False

################################################# Start CDPO!!!!!!!!!! #################################################
if __name__ == "__main__":
    CDPO().cmdloop()
