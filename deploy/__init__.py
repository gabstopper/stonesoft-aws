import boto3

class mem: 
    ec2 = None
    
def setup_default_session(**kwargs):
    mem.ec2 = boto3.resource('ec2', **kwargs)
    
import logging
try:  # Python 2.7+
    from logging import NullHandler
except ImportError:
    class NullHandler(logging.Handler):
        def emit(self, record):
            pass

logging.getLogger().addHandler(NullHandler())