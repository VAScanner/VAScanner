import json
import re
import subprocess
import traceback
import os

from helpers import openJson
from settings import CVELibFile, ProjCG, LibCG, VulDB, VulRootFile

RootMethd = VulRootFile


def write_to_json(json_file: str, key, value):
    if not os.path.exists(json_file):
        data = dict()
    else:
        with open(json_file, "r") as f:
            data = json.load(f)
    if key not in data:
        data[key] = list()
    if value not in data[key]:
        data[key].append(value)
    with open(json_file, "w") as f:
        json.dump(data, f, indent=4)

def download_jar(gav: str):
    g_a_v = gav.split(":")
    groupId = g_a_v[0]
    artifactId = g_a_v[1]
    version = g_a_v[2]
    cmd = f"mvn dependency:copy -Dartifact={groupId}:{artifactId}:{version}:jar"
    res = exec_command(cmd)
    if res["code"] == 0 :
        return True
    else:
        return res["output"]

# TODO
def find_proj_path(proj_name) -> str:
    # need to give your project's path
    pass

def exec_command(cmd, work_dir="."):
    p = subprocess.Popen(
        cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=work_dir)
    try:
        out, err = p.communicate(timeout=600)
    except subprocess.TimeoutExpired:
        p.kill()
        out, err = p.communicate()
    return_code = p.returncode
    if err:
        return {"error": err.strip().decode("utf=8"), "output": out.strip(), "code": return_code}
    else:
        return {"output": out.strip().decode(), "code": return_code}


def proj_name_analyzer(proj_url: str):
    if os.path.isdir(proj_url):
        proj_name = os.path.basename(proj_url)
    elif proj_url.__contains__('/'):
        proj_name = re.search(r'\/(.*)', proj_url).group(1)
    else:
        return {'error': 'this project may not exist in your repo.'}
    return proj_name


'''
needs classes_path, output_dir, proj_name
'''
def generate(jar_name: str, args: list):
    jarPath = os.path.join(os.path.dirname(__file__), jar_name+'.jar')
    jar_cmd = f"java -jar {jarPath} {args[0]} {args[1]} {args[2]} {args[3]}"
    try:
        res = exec_command(jar_cmd, ".")
        if "error" in res:
            print(res["error"])
            print(f"{jar_cmd}")
    except subprocess.CalledProcessError as e:
        print(e)
        print(traceback.format_exc())

# TODO
def proj_with_vul_lib_analyser(proj:str):
    vul_libs = []
    # need to give vulnerable libaries involved in projects
    return vul_libs



'''
output: [groupId, ArtifactId, Version]
for example,
input: org.springframework.data:spring-data-rest-webmvc:2.4.4.RELEASE
output: ['org.springframework.data', 'spring-data-rest-webmvc', '2.4.4.RELEASE']
'''
def gav_analyser(package_id: str):
    matcher = re.match(r"([A-Za-z0-9\.\:\_\-]+)\:([v0-9]+.*)", package_id)
    lib = matcher.group(1)
    groupId = lib.split(":")[0]
    artifactId = lib.split(":")[1]
    version = matcher.group(2)
    return [groupId, artifactId, version]

def is_dir_existed(dir: str):
    if os.path.exists(dir):
        if os.listdir(dir):
            return True
    return False


'''
get used lib method number and lib total method number
'''
def getLibCGPath(lib):
    gav = gav_analyser(lib)
    lib_cg = LibCG + os.sep + gav[0]+"_"+gav[1]+'_'+gav[2]+'.json'
    return lib_cg

def getUsedlibMethd(projMethd, libMethd):
    if type(libMethd) == dict:
        return libMethd
    used = list()
    for m in projMethd:
        if m in libMethd and m not in used:
            used.append(m)
    return used

'''
get lib total method number
'''
def getLibMethdNum(libMethd):
    if type(libMethd) == dict:
        return libMethd
    return len(libMethd)

def getVulCGPath(cve, lib):
    gav = gav_analyser(lib)
    path = VulDB + os.sep + cve+"_"+gav[0]+"_"+gav[1]+"_"+gav[2]+".json"
    return path

'''
get used lib vul-method list and relevant CVE
'''
def getUsedVulLibMethd(projMethd, lib, cves):
    usedMthd = list()
    existCVE = list()
    relatedVulroot = dict()
    usedAPI = dict()
    for cve in cves:
        path = getVulCGPath(cve, lib)
        if not os.path.exists(path):
            continue
        vulMethd = openJson(path)
        for mthd in projMethd:
            if mthd in vulMethd:
                vulroots = vulMethd[mthd]["srcRoot"]
                if cve not in relatedVulroot:
                    relatedVulroot[cve] = list()
                for root in vulroots:
                    if root not in relatedVulroot[cve]:
                        relatedVulroot[cve].append(root)
                if mthd not in usedMthd:
                    usedMthd.append(mthd)
                if cve not in existCVE:
                    existCVE.append(cve)
                if cve not in usedAPI:
                    usedAPI[cve] = []
                if mthd not in usedAPI[cve]:
                    usedAPI[cve].append(mthd)
    return usedMthd, existCVE, relatedVulroot, usedAPI



def getAllVulRootMethd(lib: str, cves):
    root = list()
    for cve in cves:
        path = getVulCGPath(cve, lib)
        if not os.path.exists(path):
            continue
        with open(path, "r") as f:
            vulCG = json.load(f)
        for mthd in vulCG:
            if vulCG[mthd]["isVulRoot"]:
                if mthd not in root:
                    root.append(mthd)
            else:
                break
    return root

'''
find all cves' used method calledFrequency
'''
def findVulCalledFreq(proj_cg_txt, all_used_methd: list, lib, cves):
    if len(all_used_methd) == 0:
        return {"error": "no use vul lib method."}
    all_root_methd = getAllVulRootMethd(lib, cves)
    all_freq = int(0)
    root_freq = int(0)
    if not os.path.exists(proj_cg_txt):
        return {"error": f"{proj_cg_txt} not exist."}
    with open(proj_cg_txt, "r") as f:
        data = f.readlines()
    for line in data:
        matcher = re.match(r"<(.*)>\s+-->\s+<(.*)>", line)
        if not matcher:
            continue
        callee = matcher.group(2)
        if callee in all_used_methd:
            all_freq = all_freq + 1
        if callee in all_root_methd:
            root_freq = root_freq + 1
    return [all_freq, root_freq]

def get_all_method_from_proj(cgfile):
    if not os.path.exists(cgfile):
        return {"error": f"{cgfile} not found."}
    with open(cgfile, "r") as f:
        cg = json.load(f)

    methods = list(cg.keys())
    for m in cg.keys():
        if cg[m]:
            for t in cg[m]:
                if t not in methods:
                    methods.append(t)
    return methods

def get_all_method_from_vulMethod(vulMethdFile):
    if not os.path.exists(vulMethdFile):
        return {"error": f"{vulMethdFile} not found."}
    with open(vulMethdFile, "r") as f:
        cg = json.load(f)
    methods = list(cg.keys())
    return methods

def get_all_method_from_lib(cgfile):
    if not os.path.exists(cgfile):
        return {"error": f"{cgfile} not found."}
    with open(cgfile, "r") as f:
        cg = json.load(f)
    methods = list()
    for gav in cg:
        for callee in cg[gav]:
            if callee not in methods:
                methods.append(callee)
            for t in cg[gav][callee]:
                if t not in methods:
                    methods.append(t)
    return methods

def write_report(data_dict, proj_name, output_dir):
    report_url = os.path.join(output_dir, proj_name+"_report.json")
    out = dict()
    out["project name"] = proj_name
    out["vulnerable dependencies"] = dict()
    out["vulnerable dependencies"] = data_dict
    with open(report_url, "w") as f:
        json.dump(out, f, indent=2)

def write_report_with_modules(data_dict, proj_name, output_dir):
    report_url = os.path.join(output_dir, proj_name + "_report.json")
    out = dict()
    out["project name"] = proj_name
    out["modules"] = data_dict
    with open(report_url, "w") as f:
        json.dump(out, f, indent=2)


def getCVEfromLib(lib):
    gav = gav_analyser(lib)
    package = gav[0]+":"+gav[1]
    cvelibDB = openJson(CVELibFile)
    cves = list()
    for cve in cvelibDB:
        if package in cvelibDB[cve]:
            if lib in cvelibDB[cve][package]:
                if cve not in cves:
                    cves.append(cve)
    return cves

def dependency_check(proj: str, proj_full_name: str):
    proj_cg_json = os.path.join(ProjCG, proj_full_name+"_cg.json")
    proj_cg_txt = os.path.join(ProjCG, proj_full_name+"_cg.txt")
    if not os.path.exists(proj_cg_json):
        return {"error": f"not found {proj_full_name}'s call graph."}
    vul_libs = proj_with_vul_lib_analyser(proj)
    if not vul_libs:
        return {"error": f"not found {proj_full_name}'s vul dependency."}
    data = dict()
    for lib in vul_libs:
        gav = gav_analyser(lib)
        if type(gav) == dict:
            return {"error": f"invalid package id, {lib}"}
        lib_cg = getLibCGPath(lib)
        if not os.path.exists(lib_cg):
            continue
        cves = getCVEfromLib(lib)
        usedVulMethd = list()
        existCVE = list()
        projMethd = get_all_method_from_proj(proj_cg_json)
        libMethd = get_all_method_from_lib(lib_cg)
        usedVulMethd, existCVE, relatedRoot, usedAPI = getUsedVulLibMethd(projMethd, lib, cves)
        
        if lib not in data:
            data[lib] = dict()
        usedLibMethod = getUsedlibMethd(projMethd, libMethd)
        usedLibMethdNum = len(usedLibMethod)
        data[lib]["used-method num"] = usedLibMethdNum
        data[lib]["used method"] = usedLibMethod
        if not usedVulMethd:
            continue
        freq = findVulCalledFreq(proj_cg_txt, usedVulMethd, lib, cves)
        if type(freq) == dict:
            continue
        else:
            usedVulFreq = freq[0]
            usedRootFreq = freq[1]
        data[lib]["CVE"] = existCVE
        data[lib]["used vul-method"] = usedVulMethd
        data[lib]["vul-called frequency"] = usedVulFreq
        if usedRootFreq != 0:
            data[lib]["root vul-called frequency"] = usedRootFreq
        data[lib]["related vul root method"] = relatedRoot
        data[lib]["CVE-API"] = usedAPI
    return data




if __name__ == "__main__":
    pass

