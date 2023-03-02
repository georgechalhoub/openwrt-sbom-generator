#!/usr/bin/env python3

###############################################################################
#
# sbom-openwrt.py -- utility for cycloneDX SBOM generation of OpenWRT builds
# used for security monitoring and notification for OpenWrt.
#
# Copyright (C) 2021 Timesys Corporation
# Copyright (C) 2022 ads-tec Engineering GmbH
#
#
# This source is released under the MIT License.
#
#######################################################################################


"""
usage: sbom-openwrt.py [-h] [-b BDIR] [-o ODIR] [-d DIFF] [-i INCLUDE_NON_CPES] [-v GIT,SVN] [-D ENABLE-DEBUG]
                            [-I WRITE-intermediate] [-N MANIFEST_REPORT_NAME] [-k KCONFIG] [-u UCONFIG] [-A ADDL]
                            [-E EXCLD] [-W WHTLST] [-F SUBFOLDER_NAME] [-O OLDFORMAT]

Arguments:
  -h, --help                show this help message and exit

  -b BDIR, --build BDIR
                            OpenWrt Build Directory
  -a APPEND_EXTERNAL_CPES, --append_external_cpes
                            File containing package names and their associated CPE IDs.
  -o ODIR, --output ODIR
                            Vigiles Output Directory
  -d DIFF, --diff
                            Enable writing of packages not containing CPE IDs
  -i INCLUDE_NON_CPES, --include_non_cpes
                            Include packages in the result list not containing a CPE ID
  -ignore IGNORE_ERR_LIST, --ignore_err_list
                            File of Packages to ignore err (works in combination with -err)
  -err ERR_ON_NON_CPE , --err_on_non_cpe
                            Enable error when finding a package without CPE ID, which is
                                not included in the EXCLD whitelist.
  -v VCS, --vcs GIT,SVN     Specify used Version Control System
  -D ENABLE-DEBUG, --enable-debug
                            Enable Debug Output
  -I WRITE-intermediate, --write-intermediate
                            Save Intermediate JSON Dictionaries
  -N MANIFEST_REPORT_NAME, --name MANIFEST_REPORT_NAME
                            Custom Manifest/Report name
  -k KCONFIG, --kernel-config KCONFIG
                            Custom Kernel Config to Use
  -u UCONFIG, --uboot-config UCONFIG
                            Custom U-Boot Config to Use
  -A ADDL, --additional-packages ADDL
                            File of Additional Packages to Include
  -E EXCLD, --exclude-packages EXCLD
                            File of Packages to Exclude
  -W WHTLST, --whitelist-cves WHTLST
                            File of CVEs to Ignore/Whitelist
  -O OLDFORMAT, --oldformat
                            Enable the old (default) vigiles-openwrt format.
"""
#######################################################################################


import argparse
import os
import sys
import json

from lib.openwrt import get_config_options
from lib.manifest import write_manifest
from lib.sbom import write_manifest_cyclonesbom
import lib.packages as packages
from lib.kernel_uboot import get_kernel_info, get_uboot_info

from lib.utils import set_debug
from lib.utils import dbg, err, warn

OUTPUT_DIR = "sbom-output"


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-b",
        "--build",
        required=True,
        dest="bdir",
        help="OpenWrt Build Directory"
    )
    parser.add_argument(
        "-a",
        "--append_external_cpes",
        dest="append_external_cpes",
        help="File containing package names and their associated CPE IDs.",
        default="",
    )
    parser.add_argument(
        "-o",
        "--output",
        dest="odir",
        help="Output Directory"
    )
    parser.add_argument(
        "-d",
        "--diff",
        dest="diff",
        help="List packages enabled in configuration but not provided with cpe-id",
        action="store_true",
        default=False,
    )
    parser.add_argument(
        "-i",
        "--include_non_cpes",
        dest="include_non_cpes",
        help="Include packages in the result list not containing a CPE ID",
        action="store_true",
        default=False,
    )
    parser.add_argument(
        "-ignore",
        "--ignore_err_list",
        dest="ignore_err_list",
        help="File of Packages to ignore err (works in combination with -err)",
        default="",
    )
    parser.add_argument(
        "-err",
        "--err_on_non_cpe",
        dest="err_on_non_cpe",
        help="Enable error when finding a package without CPE ID, which is not included in the EXCLD whitelist.",
        action="store_true",
        default=False
    )
    parser.add_argument(
        "-v",
        "--vcs",
        dest="vcs",
        help="Specify the VCS to use",
        default="git"
    )
    parser.add_argument(
        "-D",
        "--enable-debug",
        dest="debug",
        help="Enable Debug Output",
        action="store_true",
    )
    parser.add_argument(
        "-I",
        "--write-intermediate",
        dest="write_intm",
        help="Save Intermediate JSON Dictionaries",
        action="store_true",
    )
    parser.add_argument(
        "-N",
        "--name",
        dest="manifest_name",
        help="Custom Manifest Name",
        default="",
    )
    parser.add_argument(
        "-k",
        "--kernel-config",
        dest="kconfig",
        help="Custom Kernel Config to Use"
    )
    parser.add_argument(
        "-u",
        "--uboot-config",
        dest="uconfig",
        help="Custom U-Boot Config(s) to Use"
    )
    parser.add_argument(
        "-A",
        "--additional-packages",
        dest="addl",
        help="File of Additional Packages to Include",
    )
    parser.add_argument(
        "-E",
        "--exclude-packages",
        dest="excld",
        help="File which contains a List of Packages to Exclude"
    )
    parser.add_argument(
        "-W",
        "--whitelist-cves",
        dest="whtlst",
        help="File of CVEs to Ignore/Whitelist"
    )
    parser.add_argument(
        "-O",
        "--oldformat",
        dest="oldformat",
        action="store_true",
        help="Enable Out-Format from vigiles-openwrt"
    )
    args = parser.parse_args()

    set_debug(args.debug)

    params = {
        "write_intm": args.write_intm,
        "bdir": args.bdir.strip() if args.bdir else None,
        "append_external_cpes": args.append_external_cpes,
        "odir": args.odir.strip() if args.odir else None,
        "diff": args.diff,
        "include_non_cpes": args.include_non_cpes,
        "ignore_err_list": args.ignore_err_list,
        "err_on_non_cpe": args.err_on_non_cpe,
        "vcs": args.vcs,
        "manifest_name": args.manifest_name.strip(),
        "kconfig": args.kconfig.strip() if args.kconfig else "auto",
        "uconfig": args.uconfig.strip() if args.uconfig else "auto",
        "addl": args.addl.strip() if args.addl else "",
        "excld": args.excld.strip() if args.excld else "",
        "whtlst": args.whtlst.strip() if args.whtlst else "",
        "oldformat": args.oldformat,
    }

    if not os.path.exists(params.get("bdir")):
        err("Invalid path for Openwrt Build directory")
        sys.exit(1)
    else:
        params["bdir"] = os.path.abspath(params.get("bdir"))

    if not params.get("odir", None):
        odir = os.path.join(os.path.abspath(os.path.curdir), OUTPUT_DIR)
        if not os.path.exists(odir):
            os.mkdir(odir)
        params["odir"] = odir

    if params.get("excld"):
        if not os.path.isfile(params["excld"]):
            err(f"File {params.get('excld')} does not exist")
            sys.exit(1)
    if params.get("ignore_err_list"):
        if not os.path.isfile(params["ignore_err_list"]):
            err(f"File {params.get('ignore_err_list')} does not exist")
            sys.exit(1)

    if params.get("append_external_cpes"):
        if not os.path.isfile(params["append_external_cpes"]):
            err(f"File {params.get('append_external_cpes')} does not exist")
            sys.exit(1)

    if params.get("err_on_non_cpe"):
        if not params.get("excld") and not params.get("ignore_err_list"):
            warn("err_on_non_cpe flag passed, but no package excluded")

    dbg("OpenWrt Config: %s" % json.dumps(params, indent=4, sort_keys=True))
    return params


def collect_metadata(params):
    dbg("Getting Config Info ...")
    params["config"] = get_config_options(params)
    if not params["config"]:
        sys.exit(1)

    dbg("Getting Package List ...")
    params["packages"] = packages.get_package_info(params)

    if not params["packages"]:
        sys.exit(1)

    if "linux" in params["packages"]:
        dbg("Getting Kernel Info ...")
        get_kernel_info(params)

    dbg("Getting U-Boot Info ...")
    get_uboot_info(params)


def __main__():
    params = parse_args()
    collect_metadata(params)
    if params["oldformat"]:
        dbg("Writing old vigiles-openwrt format.")
        write_manifest(params)
        return 0
    sys.exit(write_manifest_cyclonesbom(params))


__main__()
