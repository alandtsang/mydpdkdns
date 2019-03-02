project(dserver)
cmake_minimum_required(VERSION 2.8)
#SET(CMAKE_INSTALL_PREFIX /usr/local/testmain)	#设置安装目录
SET(CMAKE_CXX_COMPILER "g++")

SET(RTE_SDK $ENV{RTE_SDK})
SET(RTE_TARGET $ENV{RTE_TARGET})
message(STATUS "RTE_SDK path：${RTE_SDK}")
message(STATUS "RTE_TARGET path：${RTE_TARGET}")

IF(NOT RTE_SDK)
	message(FATAL_ERROR "please set RTE_SDK path!")
ENDIF(NOT RTE_SDK)

#头文件目录
include_directories(${PROJECT_SOURCE_DIR}/include /usr/include)
include_directories("${RTE_SDK}/${RTE_TARGET}/include")
message(STATUS "RTE_SDK include path：${RTE_SDK}/include")

#lib连接文件目录
link_directories(${PROJECT_SOURCE_DIR}/lib /usr/local/lib)
link_directories("${RTE_SDK}/${RTE_TARGET}/lib")
message(STATUS "RTE_SDK library path：${RTE_SDK}/lib")

#指定编译器 参数
SET(CMAKE_CXX_FLAGS "-g -Wall -Wextra -ffunction-sections -O3 -include $(RTE_SDK)/${RTE_TARGET}/include/rte_config.h -msse4.2")

add_definitions(--std=c++11)

#将 src 目录下的所有源文件添加变量APP_SRC中
AUX_SOURCE_DIRECTORY(./src APP_SRC)                        

#指定编译目标及其源文件
add_executable(dserver ${APP_SRC})

#指定需要连接的lib文件  注意 这里对于几个驱动库需要强制引用  否则 会造成获取网卡总数为0的情况
target_link_libraries(dserver -Wl,--whole-archive
	pthread 	
#    libdpdk.a
	librte_ethdev.a
	librte_acl.a
	librte_pmd_af_packet.a
	librte_cfgfile.a
	librte_cmdline.a
	librte_distributor.a
	librte_eal.a
	librte_hash.a
	librte_ip_frag.a
	librte_jobstats.a
	librte_kni.a
	librte_kvargs.a
	librte_lpm.a
	librte_mbuf.a
	librte_mempool.a
	librte_meter.a
	librte_pipeline.a
	librte_pmd_bond.a
	librte_pmd_e1000.a
	librte_pmd_enic.a
	librte_pmd_fm10k.a
	librte_pmd_i40e.a
	librte_pmd_ixgbe.a
	librte_pmd_null.a
	librte_pmd_ring.a
	librte_pmd_vmxnet3_uio.a
	librte_port.a
	librte_power.a
	librte_reorder.a
	librte_ring.a
	librte_sched.a
	librte_table.a
	librte_timer.a
	rt
	m
	dl
	-Wl,--no-whole-archive)

#设置编译输出文件目录
set(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/bin)	

