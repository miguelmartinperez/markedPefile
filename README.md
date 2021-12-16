# Marked Pefile
_marked pefile_ is a wrapper of [pefile](https://github.com/miguelmartinperez/pefile). It adds a map of the bytes to identify the PE structures that each byte belongs.

## Dependencies
_marked pefile_ depends on version of [_pefile_](https://github.com/miguelmartinperez/pefile) that considers the layout of modules when they are on execution.

## Installation
You can clone `markedPefile` with its depecencise with:\
`git clone --depth 1 --recurse-submodules --shallow-submodules https://github.com/miguelmartinperez/markedPefile.git`


## Usage
```
MarkedPE(name=None, data=None, fast_load=None, max_symbol_exports=MAX_SYMBOL_EXPORT_COUNT, virtual_layout=False, valid_pages=None, base_address=None, architecture=None)
```
* name: File with the module
* data: Content of the module
* fast_load: Flag of _pefile_
* max_symbol_exports: Flag of _pefile_
* virtual_layout: Module with virtual layout structure
* valid_pages: Array of valid pages {[Ture, False, ...] | [0x76770000, None, ...]}
* base_address: Base address where was loaded the module
* architecture: Code architecture


Example:
```
pe = MarkedPE(data=data, virtual_layout=True, valid_pages=valid_page_array, base_address=base_address, architecture=32)

# Export directory name, inherited from pefile
pe.DIRECTORY_ENTRY_EXPORT.name

# Map with the identification of bytes
pe.__visited__

# The ID of X byte
pe.__visited__[X]

# The identifier of X byte
MARKS[pe.__visited__[X]]

# Comparison of X byte with a identifier
if pe.__visited__[byte_index] == MARKS['NT_HEADERS_BYTE']:
    print('Byte on {} belongs to NT HEADER'.format(byte_index))

```


## License

Licensed under the [GNU GPLv3](LICENSE) license.