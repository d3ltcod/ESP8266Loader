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
	private boolean isCode;
	
	public Segment(int offset, int size, byte[] content) {
		this.offset = offset;
		this.size = size;
		this.content = content;
		this.segmentName = calculateSegment(this.offset);
	}
	
	public int getOffset() {
		return offset;
	}

	public void setOffset(int offset) {
		this.offset = offset;
		this.segmentName = calculateSegment(this.offset);
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
	
	public boolean isCode() {
		return isCode;
	}

	private String calculateSegment(int loadAddress) {
		String result = "";
		
		if (loadAddress == Constants.USER_ROM_CODE_START) {
			result=".user_rom";
			this.isCode = true;
		}
		else if(loadAddress == Constants.USER_ROM_DATA_START) {
			result=".user_rom_data";
			this.isCode = false;
		}
		else if(loadAddress > Constants.USER_ROM_DATA_START && loadAddress <= Constants.USER_ROM_DATA_END) {
			result=".data";
			this.isCode = false;
		}
		else if(loadAddress >= Constants.IROM_START && loadAddress < Constants.IROM_END) {
			result=".irom";
			this.isCode = true;
		}
		else {
			result = ".uknown";
			this.isCode = true;
		}
			
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
