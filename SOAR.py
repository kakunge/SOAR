import requests
import time

# Auth
API_KEY = "<YOUR_API_KEY>"
headers = {"Authorization": f"Bearer {API_KEY}"}
cortexId = "cortex0"

def read_lines_from_file(file_path):
    with open(file_path, "r") as file:
        lines = file.readlines()
    return [line.strip() for line in lines]

def create_case(data):
    response = requests.post(f"http://localhost:9000/api/v1/case", json=data, headers=headers)
    
    return response

# Get case
def get_case(caseId):
    response = requests.get(f"http://localhost:9000/api/v1/{caseId}", headers=headers)
    
    return response

# Create Task in Case
def create_task(caseId, data):
    response = requests.post(f"http://localhost:9000/api/v1/case/{caseId}/task", json=data, headers=headers)
    
    return response

# Get Task
def get_task(taskId):
    response = requests.get(f"http://localhost:9000/api/v1/task/{taskId}", headers=headers)
    
    return response

# Create Observable in Case
def create_observable(caseId, data):
    response = requests.post(f"http://localhost:9000/api/v1/case/{caseId}/observable", json=data, headers=headers)
    
    return response

#Get Observable
def get_observable(observableId):
    response = requests.get(f"http://localhost:9000/api/v1/observable/{observableId}", headers=headers)
    
    return response

# Create Cortex job
def create_cortex_job(data):
    response = requests.post(f"http://localhost:9000/api/connector/cortex/job", json=data, headers=headers)
    
    return response

# Get Cortex Job
def get_cortex_job(jobId):
    response = requests.get(f"http://localhost:9000/api/connector/cortex/job/{jobId}", headers=headers)
    
    return response

# 1. Create Case
case_data = {
    "title": "002-Found suspected IP address",
    "description": "Test SOAR"
}
case_response = create_case(case_data)
case_id = case_response.json()["_id"]

# 2. Create Task
task_data = {
    "title": "Watch IP"
}
task_response = create_task(case_id, task_data)
task_id = task_response.json()["_id"]

# 3. Add Observable
tor_addresses = read_lines_from_file("tor_addresses.txt")
observableIds = []

for tor_address in tor_addresses:
    observable_data = {"dataType": "ip", "data": tor_address}
    observable_response = create_observable(case_id, observable_data)
    observable_id = observable_response.json()[0]["_id"]
    observableIds.append(observable_id)
    # print(observable_id, tor_address)

# 4. Create Cortex Job
analyzerIds = {}

for res in requests.get(f"http://localhost:9000/api/connector/cortex/analyzer", headers=headers).json():
    if res["name"] == "ThreatMiner_1_0":
        analyzerIds["ThreatMiner_1_0"] = res["id"]
    elif res["name"] == "TorProject_1_0":
        analyzerIds["TorProject_1_0"] = res["id"]
    elif res["name"] == "Urlscan_io_Search_0_1_1":
        analyzerIds["Urlscan_io_Search_0_1_1"] = res["id"]

# print(analyzerIds["ThreatMiner_1_0"])
# print(analyzerIds["TorProject_1_0"])
# print(analyzerIds["Urlscan_io_Search_0_1_1"])

cortexJobIDs = {}

for observable_id in observableIds:
    for analyzer_id in analyzerIds:
        cortex_job_data = {
            "analyzerId": analyzer_id,
            "cortexId": cortexId,
            "artifactId": observable_id
        }
        cortex_job_response = create_cortex_job(cortex_job_data)
        cortexJobIDs[cortex_job_response.json()["_id"]] = observable_id

time.sleep(1 * len(cortexJobIDs))

# 5. Print Result
for cortex_job_id, observable_id in cortexJobIDs.items():
    cortex_job_response = get_cortex_job(cortex_job_id).json()
    if "report" in cortex_job_response:
        if "full" in cortex_job_response["report"]:
            if "node" in cortex_job_response["report"]["full"]:
                observable_response = get_observable(observable_id).json()

                with open("log.txt", "a") as file:
                    file.write(f"Tor Node : {observable_response['data']} {cortex_job_response['report']['full']['node']}\n")
                print(f"Tor Node : {observable_response['data']} {cortex_job_response['report']['full']['node']}")


