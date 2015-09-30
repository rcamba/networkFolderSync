import string
import subprocess
from os import stat, listdir, system, path, getcwd
from shutil import copy, copytree
from ctypes import windll
from collections import OrderedDict
from ConfigParser import RawConfigParser
import argparse

#TODO:
#Conflicts when missed sync
#https://gitpython.readthedocs.org/en/stable/tutorial.html#the-index-object
#Git add, git commit files, commit message is timestamp

def create_config(args):

	if (len(args) == 2):
		args.append("") # empty EXPECTED_SSID

	elif (len(args) == 3):
		pass

	else:
		raise Exception("Invalid args: {args}.\nMust be either 2 or 3 variables. LOC_DIR_PATH NETWORK_DIR_PATH  [EXPECTED_SSID]".format(args=args))

	path_to_module = path.dirname(__file__)
	if len(path_to_module) == 0:
		path_to_module = "."

	CONFIG_FILE = path.join(path_to_module, "config.conf")

	conf_parser = RawConfigParser()

	targ_section = "networkFolderSync"
	if args[0] == ".":
		args[0] = getcwd()
	if not path.isdir(args[0]):
		raise Exception("Invalid directory argument: " + args[0])
	if not path.isdir(args[1]):
		raise Exception("Invalid directory argument: " + args[1])

	config_data_dict = OrderedDict(
		(
			("LOC_DIR_PATH", args[0]),
			("NETWORK_DIR_PATH", args[1]),
			# ("PI_USER", args[2]),
			# ("PI_PASSWORD", args[3]),
			("EXPECTED_SSID", args[2])
		)
	)

	conf_parser.add_section(targ_section)
	conf_parser.optionxform = str

	for key in config_data_dict.keys():
		conf_parser.set(targ_section, key, config_data_dict[key])

	with open(CONFIG_FILE, 'wb') as configfile:
		conf_parser.write(configfile)

def load_global_config():

	global NETWORK_DIR_PATH
	global LOC_DIR_PATH
	global EXPECTED_SSID
	# global PI_USER
	# global PI_PASSWORD

	path_to_module = path.dirname(__file__)
	if len(path_to_module) == 0:
		path_to_module = "."

	conf_parser = RawConfigParser()
	CONFIG_FILE = path.join(path_to_module, "config.conf")
	conf_parser.read(CONFIG_FILE)

	targ_section = "networkFolderSync"
	NETWORK_DIR_PATH = conf_parser.get(targ_section, "NETWORK_DIR_PATH")
	LOC_DIR_PATH = conf_parser.get(targ_section, "LOC_DIR_PATH")
	EXPECTED_SSID = conf_parser.get(targ_section, "EXPECTED_SSID")
	# PI_USER = conf_parser.get(targ_section, "PI_USER")
	# PI_PASSWORD = conf_parser.get(targ_section, "PI_PASSWORD")


def get_ssid():

	NETSH_CMD = "netsh wlan show interface"
	proc = subprocess.Popen(NETSH_CMD.split(), stdout=subprocess.PIPE,
							shell=True)
	(out, err) = proc.communicate()
	try:
		ssid_line = next(line for line in out.split("\n")
						 if "SSID" in line and "BBSID" not in line)
		ssid = ssid_line.split(":")[1].strip()
	except StopIteration:
		ssid = ""

	return ssid

def validate_ssid(ssid, EXPECTED_SSID):

	valid = False

	if ssid == EXPECTED_SSID:
		valid = True

	return valid

def get_unused_drive_letter():

	# http://stackoverflow.com/questions/827371/is-there-a-way-to-list-all-the-available-drive-letters-in-python
	unused_drive_letter = None
	bitmask = windll.kernel32.GetLogicalDrives()
	for letter in string.uppercase[::-1]: # reverse - start at Z
		if not bitmask & 1:
			unused_drive_letter = letter
			break
		bitmask >>= 1

	if unused_drive_letter is None:
		raise Exception("No drive letter is available")

	return unused_drive_letter

def map_network_drive(drive_letter, NETWORK_DIR_PATH, username=None, password=None):

	sys_cmd = "net use {drive_letter}: {NETWORK_DIR_PATH} {password} /USER:{username}".format(
		drive_letter=drive_letter, NETWORK_DIR_PATH=NETWORK_DIR_PATH, password=password, username=username)
	print sys_cmd
	system(sys_cmd)


def unmap_network_drive(drive_letter):

	sys_cmd = "net use {drive_letter} /delete".format(drive_letter=drive_letter)
	system(sys_cmd)

def get_files_list(targdir):

	return [path.join(targdir, file) for file in listdir(targdir)]

def get_newest_files(targ_files, comparison_files):

	newest_files = []

	comparison_filenames = map(path.basename, comparison_files)

	for file_ in targ_files:

		if (path.basename(file_) not in comparison_filenames):
			newest_files.append(file_)
		else:
			comp_file_mtime = round(stat(comparison_files[comparison_filenames.index(path.basename(file_) )]).st_mtime / 1000)
			targ_file_mtime = round(stat(file_).st_mtime / 1000)

			if targ_file_mtime > comp_file_mtime:
				newest_files.append(file_)

	return newest_files


# def upload_difference(drive_letter, NETWORK_DIR_PATH, username, password, newest_files):
def upload_files(targ_dir, file_list):

	#map_network_drive(drive_letter, NETWORK_DIR_PATH, username, password)

	for file_ in file_list:
		print "Copying: {file_} to {targ_dir} ".format(file_=file_, targ_dir=targ_dir)
		if path.isfile(file_):
			copy(file_, targ_dir)
		else:

			copytree(file_, targ_dir+"\\"+path.basename(file_))

	#unmap_network_drive(drive_letter)


def main():

	load_global_config()

	network_files = get_files_list(NETWORK_DIR_PATH)
	loc_files = get_files_list(LOC_DIR_PATH)

	# drive_letter = get_unused_drive_letter()

	newest_loc_files = get_newest_files(loc_files, network_files)
	newest_network_files = get_newest_files(network_files, loc_files)

	if len(newest_loc_files) == 0 and len(newest_network_files) == 0:
		print "No files to be synced"
	else:
		if len(newest_loc_files) > 0:
			upload_files(NETWORK_DIR_PATH, newest_loc_files)

		if len(newest_network_files) > 0:
			upload_files(LOC_DIR_PATH, newest_network_files)


if __name__ == '__main__':
	parser = argparse.ArgumentParser(description="Sync folder between two networks")
	parser.add_argument("-c", nargs=2, metavar=("LOC_DIR_PATH","NETWORK_DIR_PATH"), help="Create config file")
	args = parser.parse_args()
	if args.c:
		create_config(args.c)
	else:
		main()