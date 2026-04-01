#!/bin/bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROHOST_XML="${ROOT_DIR}/Panix_Sentinel Pro Pro Host.xml"
SMARTHOST_XML="${ROOT_DIR}/Panix_Sentinel Pro Smart Host.xml"
XSD_FILE="${ROOT_DIR}/docs/racepoint_component_profile.xsd"

if ! command -v xmllint >/dev/null 2>&1; then
  echo "xmllint is required (install Xcode command line tools)."
  exit 1
fi

if [[ ! -f "${XSD_FILE}" ]]; then
  echo "XSD not found: ${XSD_FILE}"
  echo "Drop racepoint_component_profile.xsd into docs/ to enable schema validation."
  exit 1
fi

echo "Validating XML profiles against ${XSD_FILE}"
xmllint --noout --schema "${XSD_FILE}" "${PROHOST_XML}"
xmllint --noout --schema "${XSD_FILE}" "${SMARTHOST_XML}"
echo "XML validation OK"
