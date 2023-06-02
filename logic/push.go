package logic

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"image-tar-push/util"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/docker/distribution"
	"github.com/docker/distribution/manifest/schema2"
	"github.com/mholt/archiver/v3"
	"github.com/opencontainers/go-digest"
	"github.com/sirupsen/logrus"
)

type ImagePush struct {
	archivePath      string
	registryEndpoint string
	username         string
	password         string
	tmpDir           string
	chunkSize        int64
	httpClient       *http.Client
	logger           *logrus.Logger
}

const (
	B = 1 << (10 * iota)
	KB
	MB
	GB
	TB
	PB
	EB
)

// NewPusher new
func NewPusher(archivePath, registryEndpoint string, skipTlsVerify bool, username, password string, chunkSize int64) (*ImagePush, error) {
	registryEndpoint = strings.TrimSuffix(registryEndpoint, "/")
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: skipTlsVerify},
	}
	if len(archivePath) == 0 {
		return nil, fmt.Errorf("archivePath is required")
	}
	if username == "" {
		return nil, fmt.Errorf("username is required")
	}
	if password == "" {
		return nil, fmt.Errorf("password is required")
	}
	if chunkSize <= 0 {
		chunkSize = 20 * MB
	}

	logger := logrus.New()
	logger.SetFormatter(&logrus.TextFormatter{})
	logger.SetOutput(os.Stdout)

	return &ImagePush{
		archivePath:      archivePath,
		registryEndpoint: registryEndpoint,
		username:         username,
		password:         password,
		tmpDir:           "/tmp/",
		httpClient:       &http.Client{Transport: tr},
		chunkSize:        chunkSize,
		logger:           logger,
	}, nil
}

// Manifest manifest.json
type Manifest struct {
	Config   string   `json:"Config"`
	RepoTags []string `json:"RepoTags"`
	Layers   []string `json:"Layers"`
}

// Push push archive image
func (i *ImagePush) Push() (err error) {
	//判断tar包是否正常
	if !util.Exists(i.archivePath) {
		i.logger.Errorf("%s not exists", i.archivePath)
		return fmt.Errorf("%s not exists", i.archivePath)
	}

	i.tmpDir = fmt.Sprintf("/tmp/docker-tar-push/%d", time.Now().UnixNano())
	i.logger.Infof("extract archive file %s to %s", i.archivePath, i.tmpDir)

	defer func() {
		err := os.RemoveAll(i.tmpDir)
		if err != nil {
			i.logger.Errorf("remove tmp dir %s error, %v", i.tmpDir, err)
		}
	}()

	err = archiver.Unarchive(i.archivePath, i.tmpDir)
	if err != nil {
		i.logger.Errorf("unarchive failed, %+v", err)
		return
	}
	data, err := os.ReadFile(i.tmpDir + "/manifest.json")
	if err != nil {
		i.logger.Errorf("read manifest.json failed, %+v", err)
		return err
	}

	var manifestObjs []*Manifest
	err = json.Unmarshal(data, &manifestObjs)
	if err != nil {
		i.logger.Errorf("unmarshal manifest.json failed, %+v", err)
		return err
	}
	for _, manifestObj := range manifestObjs {
		i.logger.Infof("start push image archive %s", i.archivePath)
		for _, repo := range manifestObj.RepoTags {
			ary := strings.Split(repo, ":")
			u, _ := url.Parse(i.registryEndpoint)
			image, tag := ary[0], ary[1]
			image = strings.TrimPrefix(strings.TrimPrefix(image, u.Host), "/")

			i.logger.Infof("image=%s,tag=%s", image, tag)

			//push layer
			i.logger.Infof("start push layer")
			var layerPaths []string
			for _, layer := range manifestObj.Layers {
				layerPath := i.tmpDir + "/" + layer
				err = i.pushLayer(layer, image)
				if err != nil {
					i.logger.Errorf("pushLayer %s Failed, %v", layer, err)
					return err
				}
				layerPaths = append(layerPaths, layerPath)
			}

			//push image config
			i.logger.Infof("start push image config")
			err = i.pushConfig(manifestObj.Config, image)
			if err != nil {
				i.logger.Errorf("push image config failed,%+v", err)
				return err
			}

			//push manifest
			i.logger.Infof("start push manifest")
			err = i.pushManifest(layerPaths, manifestObj.Config, image, tag)
			if err != nil {
				i.logger.Errorf("push manifest error,%+v", err)
				return err
			}
			i.logger.Infof("push manifest done")
		}
	}
	i.logger.Infof("push image archive %s done", i.archivePath)
	return nil
}

func (i *ImagePush) checkLayerExist(file, image string) (bool, error) {
	hash, err := util.Sha256Hash(file)
	if err != nil {
		return false, err
	}
	reqPath := fmt.Sprintf("%s/v2/%s/blobs/%s", i.registryEndpoint, image,
		fmt.Sprintf("sha256:%s", hash))
	req, err := http.NewRequest("HEAD", reqPath, nil)
	if err != nil {
		return false, err
	}
	i.logger.Debugf("HEAD %s", reqPath)
	resp, err := i.doReqWithAuth(req)
	if err != nil {
		return false, err
	}
	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusNotFound {
			return false, nil
		}
		return false, fmt.Errorf("head %s failed, statusCode is %d", reqPath, resp.StatusCode)
	}
	return true, nil
}

func (i *ImagePush) pushManifest(layersPaths []string, imageConfig, image, tag string) error {
	configPath := i.tmpDir + "/" + imageConfig
	obj := &schema2.Manifest{}
	obj.SchemaVersion = schema2.SchemaVersion.SchemaVersion
	obj.MediaType = schema2.MediaTypeManifest
	obj.Config.MediaType = schema2.MediaTypeImageConfig
	configSize, err := util.GetFileSize(configPath)
	if err != nil {
		return err
	}
	obj.Config.Size = configSize
	hash, err := util.Sha256Hash(configPath)
	if err != nil {
		return err
	}
	obj.Config.Digest = digest.Digest("sha256:" + hash)
	for _, layersPath := range layersPaths {
		layerSize, err := util.GetFileSize(layersPath)
		if err != nil {
			return err
		}
		hash, err := util.Sha256Hash(layersPath)
		if err != nil {
			return err
		}
		item := distribution.Descriptor{
			MediaType: schema2.MediaTypeUncompressedLayer,
			Size:      layerSize,
			Digest:    digest.Digest("sha256:" + hash),
		}
		obj.Layers = append(obj.Layers, item)
	}
	data, err := json.Marshal(obj)
	if err != nil {
		return err
	}
	reqPath := fmt.Sprintf("%s/v2/%s/manifests/%s", i.registryEndpoint, image, tag)
	req, err := http.NewRequest("PUT", reqPath, bytes.NewBuffer(data))
	if err != nil {
		return err
	}
	i.logger.Debugf("PUT %s", reqPath)
	req.Header.Set("Content-Type", schema2.MediaTypeManifest)
	resp, err := i.doReqWithAuth(req)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("put manifest failed, code is %d", resp.StatusCode)
	}
	return nil
}

func (i *ImagePush) pushConfig(imageConfig, image string) error {
	configPath := i.tmpDir + "/" + imageConfig
	// check image config exists
	exist, err := i.checkLayerExist(configPath, image)
	if err != nil {
		i.logger.Errorf("check config exist failed,%+v", err)
		return err
	}
	if exist {
		i.logger.Infof("%s Already exist", imageConfig)
		return nil
	}

	i.logger.Infof("start push image config %s", imageConfig)
	reqPath, err := i.startPushing(image)
	if err != nil {
		return fmt.Errorf("startPushing Error, %+v", err)
	}
	return i.chunkUpload(configPath, reqPath)
}

func (i *ImagePush) pushLayer(layer, image string) error {
	layerPath := i.tmpDir + "/" + layer
	// check layer exists
	exist, err := i.checkLayerExist(layerPath, image)
	if err != nil {
		i.logger.Errorf("check layer exist failed,%+v", err)
		return err
	}
	if exist {
		i.logger.Infof("%s Already exist", layer)
		return nil
	}

	i.logger.Infof("start push layer %s", layer)
	reqPath, err := i.startPushing(image)
	if err != nil {
		i.logger.Errorf("startPushing Error, %+v", err)
		return err
	}
	return i.chunkUpload(layerPath, reqPath)
}

func (i *ImagePush) chunkUpload(file, reqPath string) error {
	i.logger.Debugf("push file %s to %s", file, reqPath)
	f, err := os.Open(file)
	if err != nil {
		return err
	}
	stat, err := f.Stat() //获取文件状态
	if err != nil {
		return err
	}
	defer f.Close()
	contentSize := stat.Size()
	chunkSize := 20971520
	index, offset := 0, 0
	buf := make([]byte, chunkSize)
	h := sha256.New()
	for {
		n, err := f.Read(buf)
		if err == io.EOF {
			break
		}
		offset = index + n
		index = offset
		i.logger.Infof("Pushing %s ... %.2f%s", file, (float64(offset)/float64(contentSize))*100, "%")

		chunk := buf[0:n]

		h.Write(chunk)

		if int64(offset) == contentSize {
			sum := h.Sum(nil)
			//由于是十六进制表示，因此需要转换
			hash := hex.EncodeToString(sum)
			//last
			req, err := http.NewRequest("PUT",
				fmt.Sprintf("%s&digest=sha256:%s", reqPath, hash), bytes.NewBuffer(chunk))
			if err != nil {
				return err
			}
			i.logger.Debugf("PUT %s", reqPath)
			req.Header.Set("Content-Type", "application/octet-stream")
			req.Header.Set("Content-Length", fmt.Sprintf("%d", n))
			req.Header.Set("Content-Range", fmt.Sprintf("%d-%d", index, offset))
			resp, err := i.doReqWithAuth(req)
			if err != nil {
				return err
			}
			if resp.StatusCode != http.StatusCreated {
				return fmt.Errorf("PUT chunk layer error,code is %d", resp.StatusCode)
			}
			break
		} else {
			req, err := http.NewRequest("PATCH", reqPath, bytes.NewBuffer(chunk))
			if err != nil {
				return err
			}
			req.Header.Set("Content-Type", "application/octet-stream")
			req.Header.Set("Content-Length", fmt.Sprintf("%d", n))
			req.Header.Set("Content-Range", fmt.Sprintf("%d-%d", index, offset))
			i.logger.Debugf("PATCH %s", reqPath)
			resp, err := i.doReqWithAuth(req)
			if err != nil {
				return err
			}
			location := resp.Header.Get("Location")
			if resp.StatusCode == http.StatusAccepted && location != "" {
				reqPath = location
			} else {
				return fmt.Errorf("PATCH chunk file error,code is %d", resp.StatusCode)
			}
		}
	}
	return nil
}

func (i *ImagePush) startPushing(image string) (string, error) {
	reqPath := fmt.Sprintf("%s/v2/%s/blobs/uploads/", i.registryEndpoint, image)
	req, err := http.NewRequest("POST", reqPath, nil)
	if err != nil {
		return "", err
	}
	resp, err := i.doReqWithAuth(req)
	if err != nil {
		return "", err
	}
	location := resp.Header.Get("Location")
	if resp.StatusCode == http.StatusAccepted && location != "" {
		return location, nil
	}
	return "", fmt.Errorf("post %s status is %d", reqPath, resp.StatusCode)
}

func (i *ImagePush) doReqWithAuth(req *http.Request) (resp *http.Response, err error) {
	req.SetBasicAuth(i.username, i.password)
	resp, err = i.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusUnauthorized {
		i.logger.Errorf("Unauthorized with %s", i.username)
		return nil, fmt.Errorf("unauthorized with %s", i.username)
	}
	return resp, nil
}
