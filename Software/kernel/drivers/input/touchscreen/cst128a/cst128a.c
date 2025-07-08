/****************************************************************
* Driver modified from FocalTech driver
* Reference: ALIENTEK, leefei
****************************************************************/
#include <linux/module.h>
#include <linux/i2c.h>
#include <linux/input/mt.h>
#include <linux/of_gpio.h>
#include <linux/delay.h>
#include <linux/interrupt.h>

#define SCREEN_WIDTH  480
#define SCREEN_HEIGHT 854


/* CST128 register definitions */
#define MAX_SUPPORT_POINTS 5       // Max 5 touch points supported
#define CST128_DEVIDE_MODE_REG 0x00 // Mode register
#define CST128_TD_STATUS_REG   0x02 // Status register
#define CST128_TOUCH_DATA_REG  0x03 // Touch data start register
#define CST128_ID_G_MODE_REG   0xA4 // Interrupt mode register

/* Touch event types */
#define TOUCH_EVENT_DOWN      0x00
#define TOUCH_EVENT_UP        0x01
#define TOUCH_EVENT_ON        0x02
#define TOUCH_EVENT_RESERVED  0x03

struct hyn_cst128_dev {
    struct i2c_client *client;
    struct input_dev *input;
    int reset_gpio;
    int irq_gpio;
};

#define E_LOG(fmt, args...) printk(KERN_ERR "[CST128A/E]%s:" fmt "\n", __func__, ##args)

/* I2C write operation */
static int hyn_cst128_write(struct hyn_cst128_dev *cst128, u8 addr, u8 *buf, u16 len)
{
    struct i2c_client *client = cst128->client;
    struct i2c_msg msg;
    u8 send_buf[6] = { 0 };
    int ret;

    send_buf[0] = addr;
    memcpy(&send_buf[1], buf, len);
    msg.flags = 0;
    msg.addr = client->addr;
    msg.buf = send_buf;
    msg.len = len + 1;

    ret = i2c_transfer(client->adapter, &msg, 1);
    if (ret != 1) {
        dev_err(&client->dev, "Write error, addr=0x%x len=%d\n", addr, len);
        return -1;
    }
    return 0;
}

/* I2C read operation */
static int hyn_cst128_read(struct hyn_cst128_dev *cst128, u8 addr, u8 *buf, u16 len)
{
    struct i2c_client *client = cst128->client;
    struct i2c_msg msg[2];
    int ret;

    msg[0].flags = 0; // Write
    msg[0].addr = client->addr;
    msg[0].buf = &addr;
    msg[0].len = 1;

    msg[1].flags = I2C_M_RD; // Read
    msg[1].addr = client->addr;
    msg[1].buf = buf;
    msg[1].len = len;

    ret = i2c_transfer(client->adapter, msg, 2);
    if (ret != 2) {
        dev_err(&client->dev, "Read error, addr=0x%x len=%d\n", addr, len);
        return -1;
    }
    return 0;
}

/* Reset touch controller */
static int hyn_cst128_reset(struct hyn_cst128_dev *cst128)
{
    struct i2c_client *client = cst128->client;
    int ret;

    cst128->reset_gpio = of_get_named_gpio(client->dev.of_node, "reset-gpios", 0);
    if (!gpio_is_valid(cst128->reset_gpio)) {
        dev_err(&client->dev, "Invalid reset GPIO\n");
        return cst128->reset_gpio;
    }

    ret = devm_gpio_request_one(&client->dev, cst128->reset_gpio,
                               GPIOF_OUT_INIT_HIGH, "cst128 reset");
    if (ret < 0) 
    {
        dev_err(&client->dev, "gpio request error\n");
        return ret;
    }

    msleep(20);
    gpio_set_value_cansleep(cst128->reset_gpio, 0);
    msleep(15);
    gpio_set_value_cansleep(cst128->reset_gpio, 1);

    return 0;
}

/* Interrupt handler for touch events */
static irqreturn_t hyn_cst128_isr(int irq, void *dev_id)
{
	struct hyn_cst128_dev *cst128 = dev_id;
	u8 rdbuf[30] = { 0 };
	int i, type, x, y, id;
	bool down;
	int ret;

	/* Read CST128 touch coordinates starting from register 0x02, continuously read 30 registers */
	ret = hyn_cst128_read(cst128, CST128_TD_STATUS_REG, rdbuf, 30);
	if (ret)
		goto out;

	for (i = 0; i < MAX_SUPPORT_POINTS; i++) {
		u8 *buf = &rdbuf[i * 6 + 1];

		/* Taking the first touch point as example, register TOUCH1_XH (address 0x03), bit description:
         * bit7:6  Event flag  0:Press down 1:Release 2:Contact 3:No event
         * bit5:4  Reserved
         * bit3:0  X-axis touch point bits [11:8]
         */
		type = buf[0] >> 6; // Get touch point's Event Flag
		if (type == TOUCH_EVENT_RESERVED)
			continue;

		x = ((((buf[0] & 0x0f) << 8) | buf[1]) & 0x0fff);
		y = (((buf[2] & 0x0f) << 8) | buf[3]) & 0x0fff;

		if (x == 0 || y == 0 || x >= SCREEN_WIDTH || y >= SCREEN_HEIGHT)
			continue;
		x = SCREEN_WIDTH - x;

		/* Taking the first touch point as example, register TOUCH1_YH (address 0x05), bit description:
         * bit7:4  Touch ID  Identifies which touch point
         * bit3:0  Y-axis touch point bits [11:8]
         */
		id = (buf[2] >> 4) & 0x0f;
		down = type != TOUCH_EVENT_UP;

		input_mt_slot(cst128->input, id);
		input_mt_report_slot_state(cst128->input, MT_TOOL_FINGER, down);

		if (!down)
			continue;
		//E_LOG("position x=%d,y=%d", x, y);
		input_report_abs(cst128->input, ABS_MT_POSITION_X, x);
		input_report_abs(cst128->input, ABS_MT_POSITION_Y, y);
	}

	input_mt_report_pointer_emulation(cst128->input, true);
	input_sync(cst128->input);

out:
	return IRQ_HANDLED;
}

/* Initialize interrupt handling */
static int hyn_cst128_irq(struct hyn_cst128_dev *cst128)
{
    struct i2c_client *client = cst128->client;
    int ret;

    cst128->irq_gpio = of_get_named_gpio(client->dev.of_node, "irq-gpios", 0);
    if (!gpio_is_valid(cst128->irq_gpio)) {
        dev_err(&client->dev, "Invalid IRQ GPIO\n");
        return cst128->irq_gpio;
    }

    ret = devm_gpio_request_one(&client->dev, cst128->irq_gpio, 
                               GPIOF_IN, "cst128 interrupt");
    if (ret < 0) return ret;

    ret = devm_request_threaded_irq(&client->dev,
                                  gpio_to_irq(cst128->irq_gpio), NULL,
                                  hyn_cst128_isr,
                                  IRQF_TRIGGER_FALLING | IRQF_ONESHOT,
                                  client->name, cst128);
    if (ret) {
        dev_err(&client->dev, "Failed to request IRQ\n");
        return ret;
    }

    return 0;
}

/* Driver probe function */
static int hyn_cst128_probe(struct i2c_client *client,
                             const struct i2c_device_id *id)
{
    struct hyn_cst128_dev *cst128;
    struct input_dev *input;
    u8 data;
    int ret = 0;

    E_LOG("hyn_cst128_probe start...");
    
    cst128 = devm_kzalloc(&client->dev, sizeof(*cst128), GFP_KERNEL);
    if (!cst128) {
        dev_err(&client->dev, "Failed to allocate driver data\n");
        return -ENOMEM;
    }
    cst128->client = client;

    ret = hyn_cst128_reset(cst128);
    if (ret) return ret;

    msleep(5);

    /* Initialize device */
    data = 0;
    hyn_cst128_write(cst128, CST128_DEVIDE_MODE_REG, &data, 1);
    data = 1;
    hyn_cst128_write(cst128, CST128_ID_G_MODE_REG, &data, 1);

    ret = hyn_cst128_irq(cst128);
    if (ret) return ret;

    /* Setup input device */
    input = devm_input_allocate_device(&client->dev);
    if (!input) {
        dev_err(&client->dev, "Failed to allocate input device\n");
        return -ENOMEM;
    }

    cst128->input = input;
    input->name = "CST128 TouchScreen";
    input->id.bustype = BUS_I2C;

    input_set_abs_params(input, ABS_MT_POSITION_X, 0, SCREEN_WIDTH, 0, 0);
    input_set_abs_params(input, ABS_MT_POSITION_Y, 0, SCREEN_HEIGHT, 0, 0);

    ret = input_mt_init_slots(input, MAX_SUPPORT_POINTS, INPUT_MT_DIRECT);
    if (ret) {
        dev_err(&client->dev, "Failed to init MT slots\n");
        return ret;
    }

    ret = input_register_device(input);
    if (ret) return ret;

    i2c_set_clientdata(client, cst128);
    E_LOG("hyn_cst128_probe OK!");
    return 0;
}

/* Driver remove function */
static void hyn_cst128_remove(struct i2c_client *client)
{
    struct hyn_cst128_dev *cst128 = i2c_get_clientdata(client);
    input_unregister_device(cst128->input);
}

static const struct of_device_id hyn_cst128_of_match[] = {
    { .compatible = "hyn,cst128a" },
    { /* sentinel */ }
};
MODULE_DEVICE_TABLE(of, hyn_cst128_of_match);

static struct i2c_driver hyn_cst128_driver = {
    .driver = {
        .owner         = THIS_MODULE,
        .name          = "hyn_cst128a",
        .of_match_table = of_match_ptr(hyn_cst128_of_match),
    },
    .probe    = hyn_cst128_probe,
    .remove   = hyn_cst128_remove,
};

module_i2c_driver(hyn_cst128_driver);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("nanshou163@163.com");
MODULE_INFO(intree, "Y");