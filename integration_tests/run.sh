#!/bin/bash

echo "::group::Build katana"
rm integration-test katana-ng 2>/dev/null
cd ../cmd/katana-ng
go build
mv katana-ng ../../integration_tests/katana-ng
echo "::endgroup::"

echo "::group::Build katana integration-test"
cd ../integration-test
go build
mv integration-test ../../integration_tests/integration-test
cd ../../integration_tests
echo "::endgroup::"

./integration-test
if [ $? -eq 0 ]
then
  exit 0
else
  exit 1
fi
