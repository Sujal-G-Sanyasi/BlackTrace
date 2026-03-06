from setuptools import find_packages, setup
from typing import List
def get_requirements():
    requirement_list : List[str] = [ ]
    try:
        with open('requirements.txt', 'r') as line:
            lib = line.readlines()
            
            for line in lib:
                requirement = line.strip()
                if requirement and requirement != '-e .':
                    requirement_list.append(requirement)
    except FileNotFoundError as ferr:
        print(f"Setup Error : {ferr}")

    return requirement_list

print(get_requirements())

setup(
    name="HIDS",
    author="Sujal G Sanyasi",
    version="1.0.0",
    packages=find_packages(),
    install_requires=get_requirements()
)
    
            
