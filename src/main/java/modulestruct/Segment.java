package modulestruct;

import java.io.IOException;

import esp8266loader.Constants;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

public class Segment implements StructConverter{
	private int offset;
	private int size;
	private byte[] content;
	private String segmentName;
	
	public Segment(int offset, int size, byte[] content) {
		this.offset = offset;
		this.size = size;
		this.content = content;
		this.segmentName = calculateSegment(this.offset);
	}
	
	public int getOffset() {
		return offset;
	}

	public int getSize() {
		return size;
	}

	public byte[] getContent() {
		return content;
	}
	
	public String getSegmentName(){
		return segmentName;
	}
	
	private String calculateSegment(int loadAddress) {
		String result = "";
		
		if (loadAddress >= Constants.IROM_MAP_START && loadAddress < Constants.IROM_MAP_END)
			result="IROM";
		else if(loadAddress >= Constants.SPI_FLASH_START && loadAddress < Constants.SPI_FLASH_END)
			result="SPI_FLASH";
		else if(loadAddress >= Constants.IRAM_MAP_START && loadAddress < Constants.SPI_FLASH_START)
			result="IRAM";
		else if(loadAddress >= Constants.DRAM_MAP_START && loadAddress < Constants.DRAM_MAP_END)
			result="DRAM";
		else 
			result = "uknown";
			
		return result;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType("header_item", 0);
		
		structure.add(DWORD, 1, "offset", "Starting offset of the section");
		structure.add(DWORD, 1, "size", "Size of the section");
		structure.add(BYTE, size, "content", "Contents of the section");
		
		return structure;
	}
	
}
