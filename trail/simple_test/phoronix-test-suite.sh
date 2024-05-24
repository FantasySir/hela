#!/bin/bash

# 定义测试名称
TEST_SUITE="mbw"  # 根据需要替换测试套件名称
NO_MECHANISM_RESULT="cpu-no-mechanism"
WITH_MECHANISM_RESULT="cpu-with-mechanism"
COMPARISON_RESULT="comparison-result"
HELA="../../src/hela"

# 停止特定服务，设置无运行机制环境
setup_no_mechanism() {
    echo "Setting up no mechanism environment..."
    docker rm -f $(docker ps -aq)
    docker run -d httpd
    sleep 5   # 确保服务完全停止
}

# 启动特定服务，设置有运行机制环境
setup_with_mechanism() {
    echo "Setting up with mechanism environment..."
    docker rm -f $(docker ps -aq)
    sleep 1
    nohup $HELA &> /dev/null &
    sleep 2
    docker run -d httpd
    sleep 5   # 确保服务完全启动
}

# 运行基准测试并保存结果
run_benchmark() {
    local result_name=$1
    echo "Running benchmark and saving result as $result_name..."
    phoronix-test-suite benchmark $TEST_SUITE
    phoronix-test-suite result-file-save $result_name
}

# 比较测试结果
compare_results() {
    local result1=$1
    local result2=$2
    echo "Comparing results: $result1 vs $result2..."
    phoronix-test-suite result-file-to-comparison $result1 $result2
}

# 主执行流程
main() {
    # 无运行机制环境下的测试
    setup_no_mechanism
    run_benchmark $NO_MECHANISM_RESULT

    # 有运行机制环境下的测试
    setup_with_mechanism
    run_benchmark $WITH_MECHANISM_RESULT

    # 比较测试结果
    compare_results $NO_MECHANISM_RESULT $WITH_MECHANISM_RESULT
}

clear() {
	pkill -9 hela
}

# 执行主流程
main
clear