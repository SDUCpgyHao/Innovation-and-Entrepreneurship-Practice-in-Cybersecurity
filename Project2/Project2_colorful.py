import cv2
import numpy as np
from scipy.fftpack import dct, idct
from skimage.metrics import structural_similarity as ssim
import matplotlib.pyplot as plt

# 彩色DCT水印嵌入 
def embed_watermark_color(image, watermark, alpha=10):
    h, w, _ = image.shape
    wm_h, wm_w, _ = watermark.shape
    assert h >= wm_h * 8 and w >= wm_w * 8, "原图尺寸过小，无法嵌入水印"

    watermarked = image.copy().astype(np.float32)

    for ch in range(3):
        for i in range(wm_h):
            for j in range(wm_w):
                x, y = i * 8, j * 8
                block = watermarked[x:x+8, y:y+8, ch]
                dct_block = dct(dct(block.T, norm='ortho').T, norm='ortho')

                if watermark[i, j, ch] > 128:
                    dct_block[4, 3] += alpha
                else:
                    dct_block[4, 3] -= alpha

                idct_block = idct(idct(dct_block.T, norm='ortho').T, norm='ortho')
                watermarked[x:x+8, y:y+8, ch] = idct_block

    return np.clip(watermarked, 0, 255).astype(np.uint8)

#  彩色DCT水印提取 
def extract_watermark_color(watermarked_image, original_image, watermark_shape, alpha=10):
    wm_h, wm_w, _ = watermark_shape
    extracted = np.zeros((wm_h, wm_w, 3), dtype=np.uint8)

    for ch in range(3):
        for i in range(wm_h):
            for j in range(wm_w):
                x, y = i * 8, j * 8
                block_orig = original_image[x:x+8, y:y+8, ch].astype(np.float32)
                block_wm = watermarked_image[x:x+8, y:y+8, ch].astype(np.float32)

                dct_orig = dct(dct(block_orig.T, norm='ortho').T, norm='ortho')
                dct_wm = dct(dct(block_wm.T, norm='ortho').T, norm='ortho')

                diff = dct_wm[4, 3] - dct_orig[4, 3]
                extracted[i, j, ch] = 255 if diff > 0 else 0

    return extracted

#  攻击模拟 
def apply_attack(image, attack_type):
    attacked = image.copy()
    if attack_type == "flip":
        attacked = cv2.flip(attacked, 1)
    elif attack_type == "crop":
        h, w = attacked.shape[:2]
        attacked = attacked[h//4:3*h//4, w//4:3*w//4]
        attacked = cv2.resize(attacked, (w, h))
    elif attack_type == "contrast":
        attacked = cv2.convertScaleAbs(attacked, alpha=1.8, beta=0)
    elif attack_type == "shift":
        M = np.float32([[1, 0, 10], [0, 1, 10]])
        attacked = cv2.warpAffine(attacked, M, (attacked.shape[1], attacked.shape[0]))
    elif attack_type == "noise":
        noise = np.random.normal(0, 10, attacked.shape).astype(np.uint8)
        attacked = cv2.add(attacked, noise)
    elif attack_type == "blur":
        attacked = cv2.GaussianBlur(attacked, (5, 5), 0)
    elif attack_type == "jpeg":
        encode_param = [int(cv2.IMWRITE_JPEG_QUALITY), 50]
        _, encimg = cv2.imencode('.jpg', attacked, encode_param)
        attacked = cv2.imdecode(encimg, 1)
    return attacked

#  批量攻击测试 
def test_attacks_color(watermarked, original, watermark_bin):
    attacks = ["flip", "crop", "contrast", "shift", "noise", "blur", "jpeg"]
    results = []
    for attack_type in attacks:
        attacked = apply_attack(watermarked, attack_type)
        extracted = extract_watermark_color(attacked, original, watermark_bin.shape)

        ssim_r = ssim(watermark_bin[:, :, 0], extracted[:, :, 0])
        ssim_g = ssim(watermark_bin[:, :, 1], extracted[:, :, 1])
        ssim_b = ssim(watermark_bin[:, :, 2], extracted[:, :, 2])
        avg_ssim = (ssim_r + ssim_g + ssim_b) / 3

        results.append((attack_type, avg_ssim, extracted))

        plt.figure(figsize=(10, 2.5))
        plt.subplot(1, 3, 1); plt.imshow(cv2.cvtColor(attacked, cv2.COLOR_BGR2RGB)); plt.title(f"{attack_type} 攻击"); plt.axis('off')
        plt.subplot(1, 3, 2); plt.imshow(cv2.cvtColor(extracted, cv2.COLOR_BGR2RGB)); plt.title("提取水印"); plt.axis('off')
        plt.subplot(1, 3, 3); plt.imshow(cv2.cvtColor(watermark_bin, cv2.COLOR_BGR2RGB)); plt.title("原始水印"); plt.axis('off')
        plt.suptitle(f"攻击: {attack_type} | 平均 SSIM: {avg_ssim:.4f}")
        plt.tight_layout()
        plt.show()

    return results

#  图像显示 
def show_images_color(images, titles):
    plt.figure(figsize=(15, 5))
    for i in range(len(images)):
        plt.subplot(1, len(images), i + 1)
        plt.imshow(cv2.cvtColor(images[i], cv2.COLOR_BGR2RGB))
        plt.title(titles[i])
        plt.axis('off')
    plt.tight_layout()
    plt.show()

#  主程序 
def main():
   
    original_path = "my_photo.jpg" 
    watermark_path = "SDU_logo.jpg"  

    # 加载彩色原图
    original = cv2.imread(original_path)
    original = cv2.resize(original, (512, 512))

    # 加载彩色水印图像
    watermark = cv2.imread(watermark_path)
    watermark = cv2.resize(watermark, (64, 64))

    # 彩色水印图二值化（逐通道）
    _, r = cv2.threshold(watermark[:, :, 0], 128, 255, cv2.THRESH_BINARY)
    _, g = cv2.threshold(watermark[:, :, 1], 128, 255, cv2.THRESH_BINARY)
    _, b = cv2.threshold(watermark[:, :, 2], 128, 255, cv2.THRESH_BINARY)
    watermark_bin = cv2.merge([r, g, b])

    # 嵌入水印
    watermarked = embed_watermark_color(original, watermark_bin)

    # 提取水印
    extracted = extract_watermark_color(watermarked, original, watermark_bin.shape)
    show_images_color([original, watermarked, extracted], ["原图", "水印图", "提取水印"])

    # 攻击测试
    results = test_attacks_color(watermarked, original, watermark_bin)
    print("\n📊 攻击类型与平均SSIM相似度：")
    for attack, score, _ in results:
        print(f"{attack:10s}: SSIM = {score:.4f}")

# ------------------- 运行入口 -------------------
if __name__ == "__main__":
    main()
