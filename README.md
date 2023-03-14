# openwrt-sbom-generator
The code in this repository allows you to generate the SBOM for OpenWrt's open source router firmware using CycloneDX Software Bill of Materials (SBOM) standard. 

# Instructions 
It is highly recommended that you run this code in a local or cloud VM. To generate the SBOM: 

Run the following code, replace ~/openwrt/ with the directory where you built openwrt. 

python3 sbom-openwrt.py -b ~/openwrt/

If it runs successfully, you should tell you the output directory, in that case, it will be this: 

INFO: Writing Manifest to /home/george/sbom-openwrt/sbom-output/ath79-manifest.json
