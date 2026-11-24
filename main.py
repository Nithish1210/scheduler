# the main entry point for the application
# If anyone is going to edit this file, please make sure to Update the README.md file with any changes made to the code.
#Functions in this file are the root of the application hence found at the README.md file.

import os
import sys
import logging
from logging.handlers import RotatingFileHandler
from flask import Flask, jsonify, request