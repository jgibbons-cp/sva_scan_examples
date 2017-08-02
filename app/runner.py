import sva_scan_examples

# Build config
config = sva_scan_examples.ConfigHelper()

# get a halo object for api methods wrapper
halo = HaloGeneral(config)

sva_scan_examples.SVA_ScanExamples(halo)
