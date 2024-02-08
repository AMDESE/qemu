#!/bin/bash

#QEMU=/opt/iommufd-viommu/bin/qemu-system-x86_64
#QEMU=/opt/qemuv60-viommu/bin/qemu-system-x86_64
#QEMU=/opt/qemu_nicolinc_iommufd/bin/qemu-system-x86_64
#QEMU=/opt/qemu_yiliu1765_iommufd/bin/qemu-system-x86_64
#QEMU=/opt/qemu-iommufd_rfcv3_nesting-amd/bin/qemu-system-x86_64

#WORKING
#QEMU=/opt/qemu-iommufd_rfcv4_nesting-amd/bin/qemu-system-x86_64

#WORKING
#QEMU=/opt/qemu-iommufd_rfcv4_nesting-amd_v13/bin/qemu-system-x86_64
#QEMU=/opt/qemu-iommufd_rfcv4_nesting-amd_v16/bin/qemu-system-x86_64

#QEMU=/opt/qemu-iommufd_rfcv4_nesting-amd_v17/bin/qemu-system-x86_64
QEMU=/opt/qemu-viommu-google/bin/qemu-system-x86_64

DEV_LIST1="\
0000:81:00.2 \
"
#0000:81:00.3 \
#0000:81:00.4 \
#0000:81:00.5 \
#0000:81:00.6 \
#0000:81:00.7 \

#modprobe mlx5_core
#echo 8 > /sys/devices/pci0000:80/0000:80:01.1/0000:81:00.1/sriov_numvfs

dmesg -n8
#echo 'file drivers/iommu/amd/iommu.c +p' > /sys/kernel/debug/dynamic_debug/control
#echo 'file drivers/iommu/amd/viommu.c +p' > /sys/kernel/debug/dynamic_debug/control
#echo 'file drivers/iommu/amd/viommu.c func amd_viommu_guest_mmio_read -p' > /sys/kernel/debug/dynamic_debug/control
echo 'file drivers/iommu/amd/iommu.c func set_dte_gcr3_table +p' > /sys/kernel/debug/dynamic_debug/control
echo 'file drivers/iommu/amd/viommu.c func amd_viommu_cmdbuf_update +p' > /sys/kernel/debug/dynamic_debug/control
echo 'file drivers/iommu/amd/nested.c +p' > /sys/kernel/debug/dynamic_debug/control
##echo 'file drivers/iommu/iommu.c +p' > /sys/kernel/debug/dynamic_debug/control
/home/ssuthiku/ssuthiku.git/scripts/SMN_NBIO_IOMMU.py -v on

#########################################
# BINDING

dmesg -c > /dev/null
modprobe -r vfio-pci 
modprobe -r iommufd
modprobe -r kvm_amd
#echo 'file drivers/iommu/amd/viommu.c +p' > /sys/kernel/debug/dynamic_debug/control

for i in $DEV_LIST1
do 
	DEVID=`lspci -n -s $i| awk -F '[ :]' '{print $5" "$6}'`

	#-----------------------------------
	# Unbind the drivers
	echo "Unbinding ... $i"
	echo $i> "/sys/bus/pci/devices/$i/driver/unbind"
done

modprobe kvm_amd avic=1
modprobe iommufd
modprobe vfio-pci 
for i in $DEV_LIST1
do 
	DEVID=`lspci -n -s $i| awk -F '[ :]' '{print $5" "$6}'`

	# Bind NIC to vfio-pci
	echo "Binding ... vfio-pci $i"
	echo $DEVID > /sys/bus/pci/drivers/vfio-pci/new_id
done

########################################
#-device amd-viommu,host=0000:04:00.2,iommu-id=2,intremap=off,id=amd_viommu_1 \
#-device pxb-pcie,id=pcie.1,bus_nr=2,bus=pcie.0 \
#-device pcie-root-port,bus=pcie.0,id=rp2,slot=2 \
#-device pcie-root-port,bus=pcie.0,id=rp3,slot=3 \

#-device virtio-net-pci,id=vnet0,iommu_platform=on,disable-legacy=on,romfile= \
#-drive file=/root/viommu-kvmforum/ubuntu-18.04-100G.qcow2,if=virtio,id=disk0 \

#-device pcie-root-port,bus=pcie.1,id=rp1,slot=1 \
#-device pcie-pci-bridge,id=pcie_pci_bridge1,bus=pcie.1 \


ARGS="\
-smp 64 \
-nographic \
-object iommufd,id=iommufd0 \
-enable-kvm -M q35 -m 32G -cpu host \
-drive file=/home/ssuthiku/vm-images/ubuntu-18.04-100G-viommu.qcow2,if=virtio,id=disk0 \
-device amd-viommu,host=0000:80:00.2,iommu-id=1,intremap=off,id=amd_viommu_0,iommufd=iommufd0,translate-id=0xFFFF \
-device e1000,netdev=user.0 -netdev user,id=user.0,hostfwd=tcp::5555-:22 \
"

#DEV_IOMMU="0000:80:00.2"
if [ "$DEV_LIST1" != "" ]; then
	#ARGS="$ARGS -device amd-viommu,host=$DEV_IOMMU,iommu-id=1,intremap=off,id=amd_viommu_0"
	#ARGS="$ARGS -device amd-viommu-pci,host=$DEV_IOMMU,iommu-id=1,intremap=off,id=amd_viommu_0,bus=pcie.0"

	for j in $DEV_LIST1
	do
		#ARGS="$ARGS -device vfio-pci,parent-iommu-id=1,host=$j"
		ARGS="$ARGS -device vfio-pci,host=$j,iommufd=iommufd0,parent-iommu-id=1"
		#ARGS="$ARGS -device vfio-pci,parent-iommu-id=1,host=$j,iommufd=iommufd0"
		#ARGS="$ARGS -device vfio-pci,parent-iommu-id=1,host=$j,iommufd=on"
		#ARGS="$ARGS -device vfio-pci,parent-iommu-id=1,host=$j,bus=rp1"
		#ARGS="$ARGS -device vfio-pci,parent-iommu-id=1,host=$j,id=vfio_0,bus=pcie.0"
	done
fi

#ARGS="$ARGS \
#-device amd-viommu,host=0000:80:00.2,iommu-id=1,intremap=off,id=amd_viommu_0,iommufd=iommufd0 \
#"

#DEV_IOMMU="0000:40:00.2"
#if [ "$DEV_LIST2" != "" ]; then
#	#ARGS="$ARGS -device amd-viommu,host=$DEV_IOMMU,iommu-id=2,intremap=off,id=amd_viommu_1"
#	for j in $DEV_LIST2
#	do
#		ARGS="$ARGS -device vfio-pci,parent-iommu-id=1,host=$j"
#		#ARGS="$ARGS -device vfio-pci,parent-iommu-id=1,host=$j,bus=rp2"
#	done
#fi

# Start VM
echo Launching QEMU: $ARGS
#numactl --cpunodebind 0 --membind 0 $QEMU $ARGS
$QEMU $ARGS
