# build/

把**目标同构建**的 `libphp.so` 放在这里，例如：

```
build/libphp.so
```

然后：

```bash
python attack/p2s_ext.py symbols --elf build/libphp.so --out profiles/range.json
```

`symbols` 只读 ELF 符号表，不发任何网络请求。输出里必须有：

```
zif_system    = 0x......
zval_ptr_dtor = 0x......
```

如果二进制被 strip、找不到这两个符号，就只能改用带符号的 debug 构建，
或在目标同镜像里用 `readelf -sW` 确认；不要用别的版本的偏移硬套。

这个 profile 的 `calibrated` 是 `false`，`ht_size`/`htdata_offset` 还是 base 值；
必须先 `calibrate`，`oneclick` 才会接受它。
