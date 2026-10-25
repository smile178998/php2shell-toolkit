# build/

Put the `libphp.so` from the **same build as the target** here, for example:

```
build/libphp.so
```

Then:

```bash
python attack/p2s_ext.py symbols --elf build/libphp.so --out profiles/range.json
```

`symbols` only reads the ELF symbol table and makes no network requests. The output must contain:

```
zif_system    = 0x......
zval_ptr_dtor = 0x......
```

If the binary has been stripped and these two symbols cannot be found, you can only switch to a debug build with symbols,
or confirm with `readelf -sW` in the same image as the target; do not force-fit offsets from another version.

This profile has `calibrated` set to `false`, and `ht_size`/`htdata_offset` are still base values;
you must run `calibrate` first before `oneclick` will accept it.
