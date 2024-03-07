package cn.bestsec.vulcheck.agent;

import org.mapstruct.Mapper;
import org.mapstruct.control.DeepClone;
import org.mapstruct.factory.Mappers;

@Mapper(mappingControl = DeepClone.class)
public interface ObjectMapper {

    ObjectMapper INSTANCE = Mappers.getMapper( ObjectMapper.class);

    Object convert(Object user);

}

