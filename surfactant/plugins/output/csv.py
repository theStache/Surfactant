import csv
import os

from surfactant import pluginsystem


class CSV(pluginsystem.OutputPlugin):
    PLUGIN_NAME = "CSV"
    default_fields = [
        "Path",
        "SHA1",
        "Supplier",
        "Product",
        "Version",
        "Description",
        "Copyright",
    ]

    @classmethod
    def write(cls, sbom, outfile):
        # plugin args could be handled here to change behavior
        fields = cls.default_fields

        # match output format with pandas.DataFrame.to_csv
        # equivalent to `excel` dialect, other than lineterminator
        writer = csv.DictWriter(outfile, fieldnames=fields, lineterminator=os.linesep)
        writer.writeheader()
        if "software" in sbom:
            for sw in sbom["software"]:
                cls.write_software_entry(writer, sw, fields)

    @classmethod
    def write_software_entry(cls, writer: csv.DictWriter, software, fields: "list[str]"):
        pathkey = None
        if "Path" in fields:
            if "installPath" in software:
                # default to using "installPath"
                pathkey = "installPath"
                # use "containerPath" if it has entries but "installPath" does not
                if not software["installPath"]:
                    if "containerPath" in software and software["containerPath"]:
                        pathkey = "containerPath"

        # an entry will be created for every entry with a valid path
        for p in software[pathkey]:
            row = {}
            row["Path"] = p
            # if containerPath is being used, remove the UUID portion at the start
            if pathkey == "containerPath":
                row["Path"] = "".join(row["Path"].split("/")[1:])
            for f in fields:
                # Path already added to row info
                if f == "Path":
                    continue
                # normalize some special field names to actual SBOM field names
                fld_norm = f
                if f in ("SHA1", "SHA256", "MD5", "Version", "Description"):
                    fld_norm = str.lower(f)
                elif f == "Product":
                    fld_norm = "name"
                elif f == "Supplier":
                    fld_norm = "vendor"
                row[f] = cls.get_software_field(software, fld_norm)
            print(row)
            writer.writerow(row)

    @classmethod
    def get_software_field(cls, software, field):
        if field in software:
            return software[field]
        # Copyright field currently only gets populated from Windows PE file metadata
        if field == "Copyright":
            if "metadata" in software:
                retval = []
                for entry in software["metadata"]:
                    if "FileInfo" in entry and "LegalCopyright" in entry["FileInfo"]:
                        return entry["FileInfo"]["LegalCopyright"]
        return None