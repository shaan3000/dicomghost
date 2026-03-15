from setuptools import setup, find_packages

setup(
    name="medihunt",
    version="0.1.0",
    description="Medical Device Network Traffic Analyzer for Security Assessments",
    author="Shantanu Shastri",
    license="MIT",
    packages=find_packages(),
    python_requires=">=3.8",
    install_requires=["scapy>=2.5.0"],
)
