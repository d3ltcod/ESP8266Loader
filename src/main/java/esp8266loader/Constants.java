package esp8266loader;

public class Constants {
	
	public final static byte ESP_MAGIC_BASE_V1 = (byte) 0xE9;
	public final static byte ESP_MAGIC_BASE_V2 = (byte) 0xEA;
	public final static int IROM_MAP_START = 0x40000000;
	public final static int IROM_MAP_END = 0x40100000;
	public final static int SPI_FLASH_START = 0x40200000;
	public final static int SPI_FLASH_END = 0x40300000;
	public final static int IRAM_MAP_START = 0x40100000;	 
	public final static int DRAM_MAP_START = 0x3FFE8000;
	public final static int DRAM_MAP_END = 0x3FFFFFFF;
}
