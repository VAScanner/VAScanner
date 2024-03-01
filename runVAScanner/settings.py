import os, sys
sys.path.append(os.getcwd())
ProjDependencyFile = os.path.join(os.getcwd(), "runVAScanner", "data", "proj_dependency.json")
CVELibFile = os.path.join(os.getcwd(), "runVAScanner", "data", "db_cveLib.json")
VulRootFile = os.path.join(os.getcwd(), "runVAScanner", "data", "VulRoot.json")
VulDB = r""             # the directory for vulnerable API database
MvnRepoPath = r""       # the path for maven repository
ProjCG = r""            # the directory for projects' call graphs
LibCG = r""             # the directory for libraries' call graphs