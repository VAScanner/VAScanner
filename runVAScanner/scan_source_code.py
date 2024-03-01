import logging
import multiprocessing
import os.path
import re
import traceback
import time,sys
sys.path.append(os.getcwd())
from helpers import exec_command, proj_name_analyzer, generate, dependency_check, write_report, write_report_with_modules, download_jar, ProjCG, Report, \
    find_proj_path, openJson
from bs4 import BeautifulSoup
from datetime import datetime
from settings import MvnRepoPath, ProjDependencyFile, Report
today_date = datetime.now()
formatted_date = today_date.strftime(r"%Y%m%d")
FORMAT = "%(asctime)s - %(levelname)s - %(message)s"
logging.basicConfig(level=logging.INFO, format=FORMAT)
logger = logging.getLogger("Scan Project Source Code")

# TODO
file_handler = logging.FileHandler(f"")
file_handler.setLevel(logging.INFO)
file_handler.setFormatter(logging.Formatter(FORMAT))
logger.addHandler(file_handler)


class projSourceCode():
    # url is actually path
    def __init__(self, proj_url, proj):
        self.project_url = proj_url
        # full name
        self.proj = proj
        # short name
        self.project_name = proj_name_analyzer(proj_url)
        self.modules = self.get_module_from_pom()

    def compile(self, url):
        cwd = os.getcwd()
        cmd = f'cd {url} && mvn compile'
        logger.info(f'{cmd}')
        result = exec_command(cmd)
        os.system(f"cd {cwd}")
        if result.get("code") != 0:
            logger.error("failed to compile.")
            return {'error': 'mvn compile failed.'}
        logger.info("compile successfully.")
        return 0

    def get_module_from_pom(self):
        pom_path = os.path.join(self.project_url, "pom.xml")
        if not os.path.exists(pom_path):
            return list()
        soup = BeautifulSoup(open(pom_path, 'r', encoding='utf-8'), "lxml")
        module = soup.find('modules')
        if module:
            module_list = list()
            modules = module.find_all('module')
            if modules:
                for m in modules:
                    str = m.string
                    matcher = re.search(r"\/(.*)$", str)
                    if matcher:
                        name = matcher.group(1)
                    else:
                        name = str
                    module_list.append(name)
                return module_list
        return list()

    def get_module_url_from_pom(self):
        pom_path = os.path.join(self.project_url, "pom.xml")
        if not os.path.exists(pom_path):
            logger.error("pom.xml not found.")
            return {'error': 'pom.xml not found.'}
        soup = BeautifulSoup(open(pom_path, 'r', encoding='utf-8'), features="xml")
        module = soup.find('modules')
        if module:
            module_url = list()
            modules = module.find_all('module')
            if not modules:
                return list()
            for m in modules:
                str = m.string.replace("/", os.sep)
                module_url.append(str)
            return module_url
        else:
            return list()
    
    def get_gav_from_pom(self, url):
        pom_path = os.path.join(url, "pom.xml")
        if not os.path.exists(pom_path):
            return {'error': 'pom.xml not found.'}
        soup = BeautifulSoup(open(pom_path, 'r', encoding='utf-8'), features="lxml")
        groupId = soup.find("groupid")
        artifactId = soup.find("artifactid")
        if groupId and artifactId:
            return str(groupId.string) + ":" + str(artifactId.string)
        else:
            return {"error": "no found gav."}
    
    def get_version_from_parent_pom(self, version):
        pom_path = os.path.join(self.project_url, "pom.xml")
        if not os.path.exists(pom_path):
            return {'error': 'pom.xml not found.'}
        res = version
        if not version.__contains__("$"):
            return res
        soup = BeautifulSoup(open(pom_path, 'r', encoding='utf-8'), features="lxml")
        ret = re.match(r"\$\{(.*)\}", version)
        if ret:
            var = ret.group(1)
            find = soup.find(var)
            if find:
                res = find.string
        return res
    
    # @deprecated
    def get_dependencies_from_pom(self, url):
        pom_path = os.path.join(url, "pom.xml")
        if not os.path.exists(pom_path):
            return {'error': 'pom.xml not found.'}
        soup = BeautifulSoup(open(pom_path, 'r', encoding='utf-8'), features="lxml")
        dependencies = soup.find_all("dependency")
        res = []
        for dependency in dependencies:
            groupId = ''
            artifactId = ''
            version = ''
            for child in dependency:
                if isinstance(child, str):
                    continue
                if child.name == "groupid":
                    groupId = child.string
                if child.name == "artifactid":
                    artifactId = child.string
                if child.name == "version":
                    version = child.string
            if version.__contains__("$"):
                ret = re.match(r"\$\{(.*)\}", version)
                if ret:
                    var = ret.group(1)
                    find = soup.find(var)
                    if find:
                        version = find.string
                    else:
                        version = self.get_version_from_parent_pom(version)
            gav = groupId+":"+artifactId+":"+version
            if gav not in res:
                res.append(gav)
        if res:
            return res
        else:
            return {'error': 'dependencies not found.'}
    
    def get_dependencies_from_direct_file(self):
        direct = openJson(ProjDependencyFile)
        key = self.proj.replace("_", "/")
        return direct[key]["direct"]

    def get_dependency_path(self):
        dependencies = self.get_dependencies_from_direct_file()
        if isinstance(dependencies, dict):
            return {'error': 'dependencies found error.'}
        res = []
        for gav in dependencies:
            g_a_v = gav.split(":")
            groupId = g_a_v[0]
            artifactId = g_a_v[1]
            version = g_a_v[2]
            dir_name = os.path.join(groupId.replace(".", os.sep), artifactId, version)
            jar_name = gav.split(":")[1]+"-"+gav.split(":")[-1]+".jar"
            path = os.path.join(MvnRepoPath, dir_name, jar_name)
            if not os.path.exists(path):
                download_jar(gav)
            if not os.path.exists(path):
                continue
            if path not in res:
                res.append(path)
        return res

    
    def get_module_gav(self, module):
        module_urls = self.get_module_url_from_pom()
        if not module_urls:
            return {"error": "gav found error."}
        for url in module_urls:
            m = url.split(os.sep)[-1]
            if m == module:
                gav = self.get_gav_from_pom(self.project_url+os.sep+url)
                return gav
        return{"error": "gav found error."}

    def get_soot_entry(self):
        global module_url
        module_url = self.get_module_url_from_pom()
        class_paths = list()
        if 'error' in module_url:
            return class_paths
        if module_url:
            for module in module_url:
                cls_path = os.path.join(self.project_url, module, 'target'+os.sep+'classes')
                if os.path.exists(cls_path):
                    if os.listdir(cls_path):
                        if cls_path not in class_paths:
                            class_paths.append(cls_path)
                else:
                    module_path = os.path.join(self.project_url, module)
                    if os.path.exists(module_path):
                        if os.path.exists(cls_path):
                            if os.listdir(cls_path):
                                if cls_path not in class_paths:
                                    class_paths.append(cls_path)

        else:
            cls_path = os.path.join(self.project_url, 'target'+os.sep+'classes')
            if os.path.exists(cls_path):
                if os.listdir(cls_path):
                    if cls_path not in class_paths:
                        class_paths.append(cls_path)

        return class_paths

    def generate_cg(self, output_dir: str):
        global proj_full_name, args
        proj_name = proj_name_analyzer(self.project_url)
        if type(proj_name) == dict:
            logger.error(proj_name['error'])
            return
        cgPath = os.path.join(ProjCG, proj_name+"_cg.json")
        if os.path.exists(cgPath):
            logger.info(f"{proj_name}'s CG has already existed.")
            return 0
        logger.info(f'generate call graph, {self.project_name}.')
        class_paths = self.get_soot_entry()
        if not class_paths:
            logger.error(f"{proj_name}'s classes path don't found.")
            return
        for cp in class_paths:
            start = time.time()
            args = list()
            module_name = proj_name_analyzer(cp.replace(os.sep+'target'+os.sep+'classes', ''))
            if proj_name == module_name:
                proj_full_name = module_name
            else:
                proj_full_name = proj_name+'_'+module_name
            cgPath = os.path.join(ProjCG, proj_full_name+"_cg.json")
            if os.path.exists(cgPath):
                logger.info(f"{proj_name}'s CG has already existed.")
                continue
            dependency_paths = self.get_dependency_path()
            path = ",".join(dependency_paths)
            args.append(path) # dependency paths
            args.append(cp)  # classes path
            args.append(output_dir)  # output dir
            args.append(proj_full_name)
            logger.info(f'call graph generating... {proj_full_name}.')
            try:
                p = multiprocessing.Process(target=generate, args=('repoCG', args))
                p.start()
                p.join()
            except Exception:
                logger.error(f"failed to generate cg, {proj_full_name}")
                logger.exception(traceback.format_exc())
            else:
                if p.exitcode != 0:
                    logger.error(f"failed to generate cg, {proj_full_name}")
                else:
                    if not os.path.exists(cgPath):
                        logger.error(f"failed to generate cg, {proj_full_name}")
                    else:
                        cgData = openJson(cgPath)
                        if cgData:
                            end = time.time()
                            proc_time = float((end-start)/60)
                            logger.info(f"generated cg successfully, {proj_full_name}, total time: {proc_time} min.")
                        else:
                            os.remove(cgPath)
                            logger.error(f"failed to generate cg, {proj_full_name}")

        return 0

    def dependency_check(self, output_dir):
        if type(self.project_name) == dict:
            logger.error(self.project_name["error"])
            return
        if os.path.exists(os.path.join(output_dir, self.project_name+"_report.json")):
            logger.info(f"has processed {self.project_name}.")
            return
        logger.info(f"dependency check, {self.project_name}")
        start = time.time()
        if not self.modules:
            data = dependency_check(self.proj, self.project_name)
            if "error" in data:
                logger.error(f"failed to dependency check, {self.project_name}.")
                logger.error(data["error"])
                return
            write_report(data, self.project_name, output_dir)
            end = time.time()
            proc_time = float((end-start)/60)
            logger.info(f"get dependency check report successfully, {self.project_name}, total time: {proc_time} min.")
            return

        new_data = dict()
        for module in self.modules:
            data = dependency_check(self.proj, self.project_name+"_"+module)
            if "error" in data:
                logger.error(f"failed to dependency check, {self.project_name}/{module}.")
                logger.error(data["error"])
                continue
            module_gav = self.get_module_gav(module)
            if not module_gav:
                module_key = module
            else:
                module_key = module_gav
            if module_key not in new_data:
                new_data[module_key] = dict()
                new_data[module_key]["vulnerable dependencies"] = data
        if new_data:
            write_report_with_modules(new_data, self.project_name, output_dir)
            end = time.time()
            proc_time = float((end-start)/60)
            logger.info(f"get dependency check report successfully, {self.project_name}, total time: {proc_time} min.")
        else:
            logger.info(f"dependency check's return data is null, {self.project_name}.")
        return

    def trigger_scan(self, cg_dir=ProjCG, report_dir=Report):
        if type(self.project_name) == dict:
            logger.error(f"{self.project_url} doesn't exist.")
            return
        if os.path.exists(os.path.join(report_dir, self.project_name+"_report.json")):
            logger.info(f"has processed {self.project_name}.")
            return
        logger.info(f"Start to process {self.project_name}.")
        compile_code = self.compile(self.project_url)
        cg_code = self.generate_cg(cg_dir)
        if cg_code == 0:
            self.dependency_check(report_dir)

# trigger
def run_single_case(proj):
    proj_name = proj.replace("/", "_")
    proj_path = find_proj_path(proj_name)
    scan = projSourceCode(proj_path, proj)
    scan.trigger_scan(ProjCG, Report)


if __name__ == '__main__':
    pass