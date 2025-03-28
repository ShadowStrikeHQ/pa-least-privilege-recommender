# pa-least-privilege-recommender
Analyzes existing permissions and suggests the least privileged set of permissions required for a user or group to perform a specific task based on recorded activity. Uses `psutil` to monitor process activity and `acl` library to compare and reduce required privileges. - Focused on Tools for analyzing and assessing file system permissions

## Install
`git clone https://github.com/ShadowStrikeHQ/pa-least-privilege-recommender`

## Usage
`./pa-least-privilege-recommender [params]`

## Parameters
- `-h`: Show help message and exit
- `--user`: The username to analyze.
- `--group`: The groupname to analyze.
- `--pid`: The process ID to monitor.
- `--duration`: No description provided
- `--output`: The file to write recommended permissions to.
- `--baseline`: Path to a file containing a baseline ACL to compare against.

## License
Copyright (c) ShadowStrikeHQ
