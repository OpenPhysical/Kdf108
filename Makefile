# Everyday work uses the dotnet CLI directly:
#   dotnet build          build everything
#   dotnet test           fast lane (tests/fast.runsettings: everything except the CAVP gates)

GATES = CAVP-SP800-108 CAVP-SP800-56A-ECC-ZZ CAVP-SP800-56A-ECC-KDF CAVP-SP800-56A-FFC-ZZ \
        CAVP-SP800-56A-FFC-KDF CAVP-SP800-56A-ECC-KC CAVP-SP800-56A-FFC-KC
FRAMEWORK ?= net10.0
RESULTS = artifacts/test-results

.PHONY: cavp docs docs-serve

# Runs and verifies every CAVP gate exactly as CI does (about two minutes on a laptop).
cavp:
	dotnet build tests/Kdf108.Test -c Release -f $(FRAMEWORK)
	@for gate in $(GATES); do \
		rm -rf $(RESULTS)/$$gate; \
		dotnet test tests/Kdf108.Test -c Release -f $(FRAMEWORK) --no-build --settings tests/cavp.runsettings \
			--filter "TestCategory=$$gate" --logger "trx;LogFileName=$$gate.trx" --results-directory $(RESULTS)/$$gate || exit 1; \
		pwsh -NoProfile -File tests/verify-conformance-results.ps1 -ResultsDirectory $(RESULTS)/$$gate -GateName $$gate || exit 1; \
	done

docs:
	docfx docfx.json

docs-serve:
	docfx docfx.json --serve
