from setuptools import setup

def readme():
    with open('README.rst') as f:
        return f.read()
    
setup(name='stonesoft-aws',
      version='0.2',
      description='Stonesoft NGFW deployer for AWS',
      url='http://github.com/gabstopper/stonesoft-aws',
      author='David LePage',
      author_email='dwlepage70@gmail.com',
      license='Apache 2.0',
      packages=['deploy'],
      install_requires=[
          'smc-python>=0.3.8',
          'boto3',
          'ipaddress',
          'pyyaml'
      ],
      #pip install git+https://github.com/gabstopper/stonesoft-aws.git --process-dependency-links
      dependency_links=['https://github.com/gabstopper/smc-python/tarball/master#egg=smc-python-0.3.8'],
      include_package_data=True,
      classifiers=[
        "Programming Language :: Python :: 2.7",
        ],
      zip_safe=False)
