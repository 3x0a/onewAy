# onewAy
> ⚠️ This project is currently in early development and you should expect breaking changes as well as unfinished features.

onewAy is a red team security tool inspired by Armitage. onewAy aims to be not only a GUI for Metasploit but an entire framework within itself. This tool is split into three main parts, the server/frontend, the server/backend, and the client. This framework uses plug-in style modules that allow operators to define custom modules and upload them to already running clients.


### server/fronted (React + TypeScript)
This is the UI frontend for the red team operater.

### server/backend (Python - FastAPI + PostgreSQL)
This is where the database and FastAPI backend lives and what the server/frontend talks to.

### client (Rust)
This is the templete code that gets compiled and put on the target machine.
