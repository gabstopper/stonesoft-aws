from setuptools import setup, find_packages

def readme():
    with open('README.rst') as f:
        return f.read()

setup(name='stonesoft-aws',
      version='0.2.3',
      description='Stonesoft NGFW deployer for AWS',
      url='http://github.com/gabstopper/stonesoft-aws',
      author='David LePage',
      author_email='dwlepage70@gmail.com',
      license='Apache 2.0',
      packages=find_packages(),
      include_package_data=True,
      install_requires=[
          'smc-python==0.4.1',
          'boto3',
          'ipaddress',
          'pyyaml'
      ],
      entry_points={
        'console_scripts': [
                'ngfw_launcher=deploy.__main__:main'
        ]
      },
      #pip install git+https://github.com/gabstopper/stonesoft-aws.git --process-dependency-links
      dependency_links=['https://github.com/gabstopper/smc-python/tarball/master#egg=smc-python-0.4.1'],
      classifiers=[
        "Programming Language :: Python :: 2.7",
        "Topic :: System :: Networking :: Firewalls",
        ],
      zip_safe=False)