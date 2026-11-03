#include <idc.idc>

// Run with File > Script file after IDA's autoanalysis completes.
// Choose the output configured as ghidra.functions in project.toml.
static csv_name(name)
{
    auto result, i, character;
    result = "";
    for (i = 0; i < strlen(name); i++) {
        character = substr(name, i, i + 1);
        result = result + character;
        if (character == "\"") result = result + character;
    }
    return result;
}

static main()
{
    auto path, file, address, end;
    path = ask_file(1, "functions.csv", "Export function inventory");
    if (path == 0) return;
    file = fopen(path, "w");
    if (file == 0) {
        warning("Cannot write %s", path);
        return;
    }
    fprintf(file, "address,size,name\n");
    for (address = get_next_func(0); address != BADADDR; address = get_next_func(address)) {
        end = get_func_attr(address, FUNCATTR_END);
        fprintf(file, "0x%08x,%d,\"%s\"\n", address, end - address,
            csv_name(get_func_name(address)));
    }
    fclose(file);
    msg("Exported function inventory to %s\n", path);
}
