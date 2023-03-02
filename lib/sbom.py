###########################################################################
#
# lib/sbom.py - Helper for generation cycloneDX SBOM
#
# Copyright (C) 2022 ads-tec Engineering GmbH
#
#
# This source is released under the MIT License.
#
###########################################################################
import json
import copy

from lib.manifest import _init_manifest, _manifest_name
from lib.utils import dbg, mkdirhier, info, err

CYCLONE_SPEC_VERSION = "1.4"


def filter_non_cpe_packages(packages):
    for package_name in list(packages.keys()):
        curr_package_values = packages.get(package_name)
        if curr_package_values.get("cpe_id") == "unknown" or curr_package_values.get("cpe_id") is None:
            dbg(f"Remove Non-CPE-Package: {package_name} from list")
            del packages[package_name]
    return packages


def fill_in_package_info(packages, components_list, err_on_non_cpe, ignore_err_list):
    name_list = []
    for package_name in list(packages.keys()):
        curr_package = packages.get(package_name)
        if not curr_package.get("name") in name_list:
            name_list.append(curr_package.get("name"))
            append = True
        else:
            append = False
            for component in components_list:
                if curr_package.get("name") == component.get("name"):
                    if curr_package.get("version") != component.get("version"):
                        append = True
                        break

        curr_package.update({"group": ""})

        if curr_package.get("cpe_id") is None or "unknown" in curr_package.get("cpe_id"):
            if not err_on_non_cpe:
                curr_package.update({"cpe_id": "cpe:/a:unknown:unknown"})
                curr_package.update({"group": "Non-CPE"})
            else:
                if not ignore_err_list:
                    err(f"{package_name} has no CPE-ID! Aborting...")
                    return False
                else:
                    if package_name in ignore_err_list:
                        curr_package.update({"cpe_id": "cpe:/a:unknown:unknown"})
                        curr_package.update({"group": "Non-CPE"})
                    else:
                        err(f"{package_name} not in ignore_err_list and has no CPE-ID! Aborting...")
                        return False

        if curr_package.get("version") is None:
            curr_package.update({"version": ""})

        if "adstec" in curr_package.get("license").lower():
            curr_package.update({"group": "Ads-tec"})

        if append:
            components_list.append(
                {
                    "type": "application",
                    "supplier": {
                        "name": curr_package.get("package_supplier")
                    },
                    "group": curr_package.get("group"),
                    "name": curr_package.get("name"),
                    "version": curr_package.get("version"),
                    "licenses": [
                        {
                            "license": {
                                "name": curr_package.get("license")
                            }
                        }
                    ],
                    "cpe": curr_package.get("cpe_id") + ":" + curr_package.get("version"),
                }
            )
    return True


def generate_cyclone_sbom(packages, err_on_non_cpe, ignore_err_list):
    cyclone_sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": CYCLONE_SPEC_VERSION,
        "serialNumber": "urn:uuid:00000000-0000-0000-0000-000000000000",
        "version": 1,
        "components": []
    }
    if fill_in_package_info(packages, cyclone_sbom["components"], err_on_non_cpe, ignore_err_list):
        return cyclone_sbom
    else:
        return False


def calc_diff(full_packages, packages):
    packages = [package for package in list(full_packages.keys()) if package not in list(packages.keys())]
    for pkg_name in list(full_packages.keys()):
        curr_pkg = full_packages.get(pkg_name)
        if "adstec" in curr_pkg.get("license").lower():
            packages.remove(pkg_name)
    return packages


def convert_sbom_to_cyclonesbom(packages, diff=False, include_non_cpes=False, err_on_non_cpe=False, ignore_err_list=[]):
    full_packages = copy.deepcopy(packages)
    packages = filter_non_cpe_packages(packages)
    if diff:
        diff_pkg = calc_diff(full_packages, packages)
    else:
        diff_pkg = ""
    if include_non_cpes:
        cyclone_sbom = generate_cyclone_sbom(full_packages, err_on_non_cpe, ignore_err_list)
    else:
        cyclone_sbom = generate_cyclone_sbom(packages, err_on_non_cpe, ignore_err_list)
    return cyclone_sbom, diff_pkg


def read_package_list(todo_file):
    if todo_file:
        with open(todo_file, "r") as f:
            for line in f:
                exclude_list = line.replace("[", "")
                exclude_list = exclude_list.replace("]", "")
                exclude_list = exclude_list.strip().split(",")
        tmp_list = []
        for element in exclude_list:
            tmp = element.replace("\"", "")
            tmp = tmp.replace("\'", "")
            tmp = tmp.replace(" ", "")
            tmp_list.append(tmp)
        exclude_list = tmp_list
        return exclude_list
    else:
        return []


def exclude_packages(packages, exclude_file):
    exclude_list = read_package_list(exclude_file)
    for pkg_name in list(packages.keys()):
        if pkg_name in exclude_list:
            dbg(f"Remove excluded Package {pkg_name} from list!")
            del packages[pkg_name]

def append_external_cpes(params):
    with open(params["append_external_cpes"], "r") as f:
        data = json.load(f)
    for package_name in params["packages"].keys():
        for ext_package in list(data.keys()):
            if ext_package == package_name:
                new_val = data[ext_package]
                params["packages"][package_name]["cpe_id"] = new_val
    return params
def write_manifest_cyclonesbom(params):
    final = _init_manifest(params)
    if params.get("append_external_cpes"):
        params = append_external_cpes(params)
    if params.get("excld"):
        exclude_packages(params["packages"], params["excld"])
    cyclone_sbom, diff_pkg = convert_sbom_to_cyclonesbom(params["packages"], params["diff"], params["include_non_cpes"],
                                                         params["err_on_non_cpe"], read_package_list(params["ignore_err_list"]))
    if cyclone_sbom:
        mkdirhier(params["odir"])
        params["manifest"] = _manifest_name(params, final)
        info("Writing Manifest to %s" % params["manifest"])
        with open(params["manifest"], "w") as f:
            json.dump(cyclone_sbom, f, indent=4, separators=(",", ": "), sort_keys=True)
            f.write("\n")
        if params["diff"]:
            with open(params["manifest"] + "_diff", "w") as f:
                json.dump(diff_pkg, f)
                f.write("\n")
        return 0
    else:
        err("Error on creation of cyclone-sbom!")
        return 255
