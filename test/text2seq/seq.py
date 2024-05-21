import yaml
import msgpack

def yaml_to_binary(yaml_file_path, output_binary_file_path):
    # 从YAML文件中读取数据
    with open("mysqld.yaml", 'r') as yaml_file:
        yaml_data = yaml.safe_load(yaml_file)
	
    packed_data = msgpack.packb(yaml_data)
    
    # 将数据序列化为二进制格式
    with open(output_binary_file_path, 'wb') as binary_file:
        binary_file.write(packed_data)

    print(f"转换完成。二进制文件已保存到：{output_binary_file_path}")

# 使用示例
yaml_file_path = 'mysqld.yaml'  # YAML策略文件路径
output_binary_file_path = 'mysqld.hl'  # 输出的二进制文件路径
yaml_to_binary(yaml_file_path, output_binary_file_path)