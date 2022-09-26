cd Penglai-Enclave-sPMP/opensbi-0.9
rm -r build
make ARCH=riscv CROSS_COMPILE=riscv64-linux-gnu- PLATFORM=generic FW_PAYLOAD_PATH=../../u-boot/u-boot.bin FW_FDT_PATH=../../u-boot/opensbi_dtb/u-boot.dtb
rm -r ../../payload/penglai-1.0/fw_payload*
cp build/platform/generic/firmware/fw_payload.bin ../../payload/penglai-1.0
cd ../../payload/penglai-1.0
ls -l
../fsz.sh fw_payload.bin fw_payload.bin.out
cd ../..
