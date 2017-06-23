# CDPO
CDPO is a tool to validate, de-duplicate, combine, query, and encrypt track data recovered from a breach.

CDPO is not claiming to be 100% accurate and no one, including the developer(s) are responsible for any innacuracies, although we will try to help troubleshoot and fix issues.

Created 2017-06 by David Pany (@DavidPany)

## Running CDPO
To run CDPO and use the default database name "CDPO.sqlite":
```
CDPO.py
```

To run CDPO with a specific database name to create or load:
```
CDPO.py coolpathofdb.sqlite
```

If you are using a database that already exists, CDPO will ask if you'd like to
1. delete the existing DB and make a new one with that name
2. load the existing DB
3. keep the existing DB and make a new one with a timestmap in the name

## CDPO Commands

### Loading Clear Text Track Data Files into CDPO

```
import ..\path\to\files\*
```

### Combining Loaded Data

```
combine NEWhugeCOLLECTIONname
```
You will be prompted for the names of loaded collections to combine into NEWhugeCOLLECTIONname. Answer with "ALL" to join it all

### Query a Loaded Collection for a Subset of Data

```
query ExistingCollection
```
You will be asked for filter parameters for 
1. expiration date
2. brand
3. track data format

### Show Simple Stats for All Loaded Data

```
show
```

### Show Detailed Stats for One Collection

```
stat SuperAwesomeCollection
```

### Write Stats of All Loaded Data to CSV in Current Directory

```
csvstats
```

### Write Decrypted PAN, Expiration Date, and Track Stats of One Collection to CSV

```
file needThisCollectoin
```

### Quit CDPO

```
quit
```
or
```
exit
```

## What does CDPO do with my track data?

### How do I get started with CDPO?
1. Find Track Data output files from breach
2. Decode Track Data output files to clear text if encoded
3. Load into CDPO using the import command described above

### Does CDPO validate the track data to make sure it is real?
1. CDPO uses a track format regex to identify track formats 1 and 2.
    1. If a line in the input file doesn't match the regex, it is dropped.
2. CDPO performs Luhn validation on PANs.
    1. If the PAN doesn't validate Luhn, CDPO will test a substring of the PAN in case the malware accidentally scraped a random number before the PAN. This could be a bad idea since some card brands apparently don't require Luhn, but let's test this together :)
    2. If a PAN or it's substrings don't match Luhn, the data is dropped.
3. CDPO checks to see if the expiration month is between 1 and 12. If not, CDPO drops the record.
4. CDPO does some simple brand matching against data from https://en.wikipedia.org/wiki/Payment_card_number.
    1. This is not a perfect process. Please confirm with card brands or banks.

### Is My Database Encrypted?
1. Your input files must not be encrypted.
2. CDPO will load the data into a SQLITE database where the individual PAN (Primary Account Number) records are RC4 encrypted with a password you provide when starting CDPO.

## I Have Questions/Complaints/Requests/Errors
Feel free to make a merge request or open an issue with Github. If you need immediate assistance, please contact @DavidPany on Twitter.
