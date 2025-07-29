__author__ = "phylu"

from xml.dom import NamespaceErr

from defusedxml import ElementTree

from dojo.models import Finding, Endpoint

class CppChechkParserXMl:
    
    def get_scan_types(self):
        return ["Cppchech"]
    
    def get_label_for_scan_types(self, scan_type):
        return scan_type

    def get_description_for_scan_types(self, scan_type):
        return "XML file from SAST Scanner Cppcheck." 
    
    
    def get_findings(self, file, test):
        cppcheck_tree = ElementTree.parse(file)
        root = cppcheck_tree.getroot()
        
        if "xml-report" not in root.tag:
            msg = "This doesn't seem to be a valid Cppcheck XML file."
            raise NamespaceErr(msg)
        for error in root.findall("error"):
            id = error.get('id','')
            severity = error.get('severity','')
            verbose = error.get('verbose','')
            file0 = error.get('file0','')
            cwe = error.get('cwe','')
            

            
            for locaction in error.findall("location"):
                line = locaction.get("line", "")
                column = locaction.get("column", "")
                info = locaction.get("info", "")

                if line or column or info:
                    description += f"\n**Location:** Line {line}, Column {column}: {info}"

            # Проверяем на дубликаты
            dupe_key = f"cppcheck:{id}:{file0}"
            if dupe_key in dupes:
                find = dupes[dupe_key]
                find.description += "\n-----\n\n" + description
                find.nb_occurrences += 1
            else:
                finding = Finding(
                    title=id,
                    test=test,
                    description=description,
                    severity=finding_severity,
                    component_name=file0,
                    component_version="",
                    vuln_id_from_tool=id,
                    nb_occurrences=1,
                )
                finding.date = report_date
                dupes[dupe_key] = finding

        return list(dupes.values())
        
    
    def convert_severity(self, severity):
    
        mapping = {
            "none": 'Info',
            "style": 'Info',
            "perfomance": 'Info',
            "portatbility": 'info',
            "debug": 'Info',
            'information': 'Info',
            'warning': 'Medium',
            'error': 'High'
        }
        return mapping.get(severity, 'Medium')    
    
 
    