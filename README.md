# xcipmaster

Python 3.9.0 Installation:
1. wget https://www.python.org/ftp/python/3.9.0/Python-3.9.0.tar.xz
2. tar -xf Python-3.9.0.tar.xz
3. cd Python-3.9.0
4. ./configure --enable-optimizations
5. make -j 2 (replace 2 with the number of cores in your processor)
6. sudo make altinstall
7. python3.9 --version
[7] OUTPUT: Python 3.9.0

Set Python3.9 as default python version:
1. sudo update-alternatives --install /usr/bin/python python /usr/local/bin/python3.9 1
[1] OUTPUT: update-alternatives: using /usr/local/bin/python3.9 to provide /usr/bin/python (python) in auto mode
2. python --version
[2] OUTPUT: Python 3.9.0

Virtualenv Installation using pip:
1. python -m venv <environment_directory> # Example: python -m venv ./CIP Simulator/phase3/py3_venv (py3_venv is the environment name)
2. source <environment_directory>/bin/activate
3. python -m pip install --upgrade pip # Update the pip to latest inside virtual environment
6. pip install -r requirements.txt # Install the project dependencies from the requirements.txt file into Virtualenv
7. python main.py # Your environment is now set up. You can start running the tool
8. deactivate # You can exit the Virtualenv using deactivate command

## Testing helpers

Unit tests can instantiate the command controller directly with stubbed
dependencies. The :class:`CLI` constructor accepts optional services and a
``test_mode`` flag that skips the interactive banner, progress bar, and startup
prompts. For example::

    fake_cli = CLI(
        config_service=FakeConfigService(),
        network_service=FakeNetworkService(),
        comm_manager=FakeCommManager(),
        test_mode=True,
    )

The object can then be passed to Click's ``CliRunner`` via ``obj=fake_cli`` to
exercise commands without touching the real filesystem or network.
