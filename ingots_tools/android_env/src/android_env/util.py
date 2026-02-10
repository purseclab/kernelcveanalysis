# gets the lines of a config file, and ignores comments and empty lines
def config_lines(config: str) -> list[str]:
    out = []
    for line in config.split('\n'):
        # handle comments
        if '#' in line:
            index = line.find('#')
            line = line[:index]
        
        line = line.strip()
        if line == '':
            continue

        out.append(line)
    
    return out