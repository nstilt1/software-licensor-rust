# Power Tuning

This is a repo for determining how much RAM to use for the Lambda Functions.

Unfortunately, it would not have been possible to use the official Lambda Power Tuner, as it does not appear to support custom Protobuf requests with custom cryptography. This will have to do.

# Register Store Refactor Results

Here are some results for the `register_store_refactor` function:

Store ID: 
`TESTuiQO-Kp6JXjPeKIh7DT/iPpNFnZhN2NYT0ITpltBLqlmvJ71PoA5UU_6ZnmB4`

```
With 128 MB of RAM - 258 ms average time
With 256 MB of RAM - 285 ms average time
With 384 MB of RAM - 220 ms average time
With 512 MB of RAM - 217 ms average time
With 650 MB of RAM - 189 ms average time
With 700 MB of RAM - 181 ms average time
With 750 MB of RAM - 216 ms average time
With 800 MB of RAM - 182 ms average time
With 850 MB of RAM - 185 ms average time
With 900 MB of RAM - 49 ms average time
```

These results are a bit biased, as they include the roundtrip latency.

Upon inspecting the CloudWatch logs, I found these in the reports under billedDurationMs:
```
128 MB - 616	351	272	258
256 MB - 366	148	127	120
384 MB - 286	89	71	80
512 MB - 269	87	66	83
650 MB - 205	60	62	57
700 MB - 211	48	52	55
750 MB - 201	52	61	48
800 MB - 188	51	46	47
850 MB - 191	56	61	54
900 MB - 195	52	52	49
```

The first column is larger due to the cold boot times, and after crunching some numbers in Libre Office Calc, I found 384 MB to be the cheapest amount of RAM for non-cold starts, and 128-256 MB including cold starts in the average time.

# Create Product

Product IDs: 
* `Test1U58-dmYcq_corvrg5ca19az_Lzef`
* `TestCq16-ClKZsVOLN_zFnR9y4EWS4z9o`
* `TestGhDt-jkezEw0aV8L1Pn/bgrpz5gog`

# Create License
License code:

`7E32-F88B-4235-3198-EEB1`

# Get License

License Info: 

```
{
"TestfxcJ-uldVDjRWqIPhjc1BXqaijHN1": 
    LicenseInfo { 
        license_type: "perpetual", 
        offline_machines: [], 
        online_machines: [], 
        machine_limit: 6 
    }, 
"TestKvXk-scAX/xccsTlqCGFHnfI9_deo": 
    LicenseInfo { 
        license_type: "trial", 
        offline_machines: [], 
        online_machines: [], 
        machine_limit: 3 
    }
}
```
# License Activation

