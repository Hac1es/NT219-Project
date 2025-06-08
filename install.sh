#!/bin/bash

if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
else
    echo "Virtual environment already exists."
fi

source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

echo "Setup completed. To activate the virtual environment, run:"
echo "source venv/bin/activate"