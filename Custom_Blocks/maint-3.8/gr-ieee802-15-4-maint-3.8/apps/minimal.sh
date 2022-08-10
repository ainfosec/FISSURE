#!/bin/bash
echo | nc -u localhost 52001 | od -vsw2
