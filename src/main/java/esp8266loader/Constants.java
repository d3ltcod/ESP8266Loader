package esp8266loader;

public class Constants {
	public final static byte ESP_MAGIC_BASE_V1 = (byte) 0xE9;
	public final static byte ESP_MAGIC_BASE_V2 = (byte) 0xEA;
	public final static byte ESP_MAGIC_BASE_V2_2 = (byte) 0x04;
	public final static int USER_ROM_DATA_START = 0x3FFE8000;
	public final static int USER_ROM_DATA_END = 0x40000000;
    public final static int USER_ROM_CODE_START = 0x40100000;
    public final static int USER_ROM_CODE_END = 0x40108000;
    public final static int SPI_FLASH_START = 0x40200000;
	public final static int SPI_FLASH_END = 0x402E1010;
}
