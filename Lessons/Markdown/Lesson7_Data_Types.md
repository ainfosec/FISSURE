---
Signal data can be formatted in several ways. The intended representation for samples in files can vary in length, endianness, and signedness. Some formats are more common than others and they can vary across applications. GNU Radio is heavily integrated into FISSURE and the descriptions of the data types are provided in this lesson. Some of the more common Python format characters are also described to demonstrate how to manipulate data from sources other than GNU Radio.
 
## Table of Contents
1. [References](#references)
2. [GNU Radio Data Types](#gnu_radio)
3. [Python](#python)

<div id="references"/> 

## References

- http://blog.sdr.hu/grblocks/types.html
- https://docs.python.org/3/library/struct.html

<div id="gnu_radio"/> 

## GNU Radio Data Types

| Data Type | Size (Bytes) | Python Character | Numpy |
| :------: | :------: | :-: | :------: |
| Complex Float 64 | 2*8 | 'd' | np.float64 |
| Complex/Complex Float 32 | 2*4 | 'f' | np.float32 |
| Complex Integer 64 | 2*8 | 'q' | np.int64 |
| Complex Integer 32 | 2*4 | 'i' | np.int32 |
| Complex Integer 16 | 2*2 | 'h' | np.int16 |
| Complex Integer 8 | 2*1 | 'b' | np.int8 |
| Float 64 | 8 | 'd' | np.float64 |
| Float/Float 32 | 4 | 'f' | np.float32 |
| Integer 64 | 8 | 'q' | np.int64 |
| Integer 32 | 4 | 'i' | np.int32 |
| Int/Integer 16 | 2 | 'h' | np.int16 |
| Byte/Integer 8 | 1 | 'b' | np.int8 |

<div id="python"/> 

## Python

From https://docs.python.org/3/library/struct.html:

| Format | C Type | Python Type | Standard Size |
| :------: | :------: | :-: | :------: |
| x | pad byte | no value |  |
| c | char | bytes of length 1 | 1 |
| b | signed char | integer | 1 |
| B | unsigned char | integer | 1 |
| ? | _Bool | bool | 1 |
| h | short | integer | 2 |
| H | unsigned short | integer | 2 |
| i | int | integer | 4 |
| I | unsigned int | integer | 4 |
| l | long | integer | 4 |
| L | unsigned long | integer | 4 |
| q | long long | integer | 8 |
| Q | unsigned long long | integer | 8 |
| n | ssize_t | integer |  |
| N | size_t | integer |  |
| e |  | float | 2 |
| f | float | float | 4 |
| d | double | float | 8 |
| s | char[] | bytes |  |
| p | char[] | bytes |  |
| P | void* | integer |  |

### Examples of Converting and Writing
```
if (get_original_type == "Complex Float 64") and (get_new_type == "Complex Int 64"): 
    number_of_bytes = os.path.getsize(get_original_file)
    plot_data_formatted = struct.unpack((number_of_bytes/8)*'d', plot_data)
    np_data = np.asarray(plot_data_formatted, dtype=np.int64)
    np_data.tofile(get_new_file)
    
elif (get_original_type == "Complex Float 32") and ((get_new_type == "Complex Int 16") or (get_new_type == "Short/Int 16")):                
    number_of_bytes = os.path.getsize(get_original_file)
    plot_data_formatted = struct.unpack((number_of_bytes/4)*'f', plot_data)
    np_data = np.asarray(plot_data_formatted, dtype=np.int16)
    np_data.tofile(get_new_file)
    
elif (get_original_type == "Int/Int 32") and ((get_new_type == "Complex Float 32") or (get_new_type == "Float/Float 32")):                
    number_of_bytes = os.path.getsize(get_original_file)
    plot_data_formatted = struct.unpack((number_of_bytes/4)*'i', plot_data)
    np_data = np.asarray(plot_data_formatted, dtype=np.float32)
    np_data.tofile(get_new_file)    
    
elif ((get_original_type == "Complex Int 16") or (get_original_type == "Short/Int 16")) and ((get_new_type == "Complex Int 8") or (get_new_type == "Byte/Int 8")):                
    number_of_bytes = os.path.getsize(get_original_file)
    plot_data_formatted = struct.unpack((number_of_bytes/2)*'h', plot_data)
    np_data = np.asarray(plot_data_formatted, dtype=np.int8)
    np_data.tofile(get_new_file) 
    
elif ((get_original_type == "Complex Int 8") or (get_original_type == "Byte/Int 8")) and (get_new_type == "Complex Float 64"):                
    number_of_bytes = os.path.getsize(get_original_file)
    plot_data_formatted = struct.unpack((number_of_bytes)*'b', plot_data)
    np_data = np.asarray(plot_data_formatted, dtype=np.float64)
    np_data.tofile(get_new_file)           
```
