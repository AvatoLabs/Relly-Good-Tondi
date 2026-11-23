# RGT Interfaces Integration

`rgt-interfaces` is integrated as a local RGT workspace member.

The interface type library imports the strict Tondi Note schema. Regenerate it after changing a type and check the resulting IDs against the schema tests.

```sh
cd rgt-interfaces
bash scripts/typelib.sh
```
